package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	_ "github.com/mattn/go-sqlite3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	jwtSecret      = []byte(getenv("JWT_SECRET", "devsecret"))
	minioEndpoint  = getenv("MINIO_ENDPOINT", "localhost:9000")
	minioAccess    = getenv("MINIO_ACCESS_KEY", "minioadmin")
	minioSecret    = getenv("MINIO_SECRET_KEY", "minioadmin")
	minioUseSSL    = getenv("MINIO_USE_SSL", "false") == "true"
	sessionsDBPath = getenv("SESSIONS_DB", "sessions.db")
)

func getenv(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}

// Session represents the persisted session record stored in SQLite.
type Session struct {
	SID       string
	Token     string
	Created   time.Time
	Confirmed bool
	TokenUser string
}

var (
	db    *sql.DB
	dbMu  sync.Mutex // serialize DB schema changes/initialization
	// wsConns keeps in-memory websocket connections per SID. This is not persisted.
	wsConns = map[string][]*websocket.Conn{}
	wsMu    sync.Mutex
	upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
)

func main() {
	// open sqlite DB
	var err error
	db, err = sql.Open("sqlite3", sessionsDBPath)
	if err != nil {
		log.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	// initialize schema
	if err := initSchema(db); err != nil {
		log.Fatalf("init schema: %v", err)
	}

	port := getenv("PORT", "8080")
	r := gin.Default()
	r.Static("/", "static")

	api := r.Group("/api")
	{
		api.POST("/qr/create", handleQRCreate)
		api.POST("/qr/confirm", handleQRConfirm)
		api.GET("/k8s/namespaces", handleK8sNamespaces)
		api.POST("/photos/presign", handlePresign)
	}

	r.GET("/ws/qr/:sid", func(c *gin.Context) {
		handleWS(c.Writer, c.Request, c.Param("sid"))
	})

	log.Printf("listening on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}

func initSchema(db *sql.DB) error {
	// create sessions table if not exists
	stmt := `CREATE TABLE IF NOT EXISTS sessions (
		sid TEXT PRIMARY KEY,
		token TEXT NOT NULL,
		created_at DATETIME NOT NULL,
		confirmed INTEGER NOT NULL DEFAULT 0,
		token_user TEXT
	);`
	_, err := db.Exec(stmt)
	return err
}

func randHex(n int) string {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// createSession inserts a new session record into SQLite.
func createSession(sid, token string) error {
	_, err := db.Exec(`INSERT INTO sessions (sid, token, created_at, confirmed) VALUES (?, ?, ?, 0)`, sid, token, time.Now().UTC())
	return err
}

// getSession loads a session by sid. Returns (nil, nil) if not found.
func getSession(sid string) (*Session, error) {
	row := db.QueryRow(`SELECT sid, token, created_at, confirmed, token_user FROM sessions WHERE sid = ?`, sid)
	var s Session
	var createdStr string
	var confirmedInt int
	err := row.Scan(&s.SID, &s.Token, &createdStr, &confirmedInt, &s.TokenUser)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// parse created_at
	t, err := time.Parse(time.RFC3339Nano, createdStr)
	if err != nil {
		// fallback: try sqlite default format
		t, _ = time.Parse("2006-01-02 15:04:05", createdStr)
	}
	s.Created = t
	s.Confirmed = confirmedInt != 0
	return &s, nil
}

// confirmSession checks token and marks session as confirmed, sets token_user, and returns error if token mismatch.
func confirmSession(sid, token, user string) (string, error) {
	// atomic: verify token matches and update
	tx, err := db.Begin()
	if err != nil { return "", err }
	defer tx.Rollback()

	row := tx.QueryRow(`SELECT token FROM sessions WHERE sid = ?`, sid)
	var dbToken string
	if err := row.Scan(&dbToken); err == sql.ErrNoRows {
		return "", fmt.Errorf("session not found")
	} else if err != nil {
		return "", err
	}
	if dbToken != token {
		return "", fmt.Errorf("invalid token")
	}
	_, err = tx.Exec(`UPDATE sessions SET confirmed = 1, token_user = ? WHERE sid = ?`, user, sid)
	if err != nil { return "", err }
	if err := tx.Commit(); err != nil { return "", err }
	// generate JWT
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user,
		"sid": sid,
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	})
	tokStr, err := jwtToken.SignedString(jwtSecret)
	if err != nil { return "", err }
	return tokStr, nil
}

func handleQRCreate(c *gin.Context) {
	sid := randHex(8)
	token := randHex(6)
	if err := createSession(sid, token); err != nil {
		c.String(500, "create session: %v", err)
		return
	}
	confirmURL := fmt.Sprintf("%s/qr/confirm?sid=%s&t=%s", getBaseURL(c.Request), sid, token)
	c.JSON(200, gin.H{"sid": sid, "token": token, "confirm_url": confirmURL})
}

func getBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}

func handleQRConfirm(c *gin.Context) {
	var p struct{
		SID string `json:"sid"`
		Token string `json:"token"`
	}
	if err := c.BindJSON(&p); err != nil {
		c.String(400, "bad request: %v", err)
		return
	}

	// For demo we set user as demo-user; in real scenario authenticate the phone user
	user := "demo-user"
	tokStr, err := confirmSession(p.SID, p.Token, user)
	if err != nil {
		c.String(400, "%v", err)
		return
	}

	// notify websocket clients
	wsMu.Lock()
	conns := wsConns[p.SID]
	for _, ws := range conns {
		_ = ws.WriteJSON(gin.H{"type":"confirmed","token": tokStr})
		ws.Close()
	}
	delete(wsConns, p.SID)
	wsMu.Unlock()

	c.JSON(200, gin.H{"ok": true})
}

func handleWS(w http.ResponseWriter, r *http.Request, sid string) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil { log.Printf("ws upgrade: %v", err); return }

	// verify session exists
	s, err := getSession(sid)
	if err != nil { _ = ws.WriteJSON(gin.H{"type":"error","message":fmt.Sprintf("db error: %v", err)}); ws.Close(); return }
	if s == nil {
		_ = ws.WriteJSON(gin.H{"type":"error","message":"session not found"})
		ws.Close()
		return
	}

	wsMu.Lock()
	wsConns[sid] = append(wsConns[sid], ws)
	wsMu.Unlock()

	// keep connection open until client disconnects
	for {
		_, _, err := ws.ReadMessage()
		if err != nil { break }
	}
	ws.Close()
}

func handlePresign(c *gin.Context) {
	name := c.Query("name")
	if name == "" { c.String(400, "missing name") ; return }

	minioClient, err := minio.New(minioEndpoint, &minio.Options{Creds: credentials.NewStaticV4(minioAccess, minioSecret, ""), Secure: minioUseSSL})
	if err != nil { c.String(500, "minio init: %v", err); return }

	bucket := "photos"
	ctx := context.Background()
	// ensure bucket exists (best-effort)
	exists, err := minioClient.BucketExists(ctx, bucket)
	if err != nil {
		// try to create
		err2 := minioClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
		if err2 != nil { c.String(500, "minio bucket error: %v/%v", err, err2); return }
	} else if !exists {
		_ = minioClient.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	}

	expires := time.Minute * 15
	presignedURL, err := minioClient.PresignedPutObject(ctx, bucket, name, expires)
	if err != nil { c.String(500, "presign error: %v", err); return }
	c.JSON(200, gin.H{"url": presignedURL.String()})
}

func handleK8sNamespaces(c *gin.Context) {
	kubeconfig := getenv("KUBECONFIG", "")
	if kubeconfig == "" {
		c.JSON(200, gin.H{"namespaces": []string{}})
		return
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil { c.String(500, "kubeconfig: %v", err); return }
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil { c.String(500, "client: %v", err); return }

	nslist, err := clientset.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil { c.String(500, "list ns: %v", err); return }
	out := []string{}
	for _, ns := range nslist.Items { out = append(out, ns.Name) }
	c.JSON(200, gin.H{"namespaces": out})
}
