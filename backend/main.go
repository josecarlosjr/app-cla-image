package main

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// ── Config ───────────────────────────────────────────────────────────────────

var jwtSecret []byte

func init() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		b := make([]byte, 32)
		rand.Read(b)
		secret = hex.EncodeToString(b)
		log.Println("⚠️  JWT_SECRET not set, using random secret (tokens won't survive restarts)")
	}
	jwtSecret = []byte(secret)
}

// ── Models ───────────────────────────────────────────────────────────────────

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type TokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at"`
	User      User   `json:"user"`
}

type User struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Role     string `json:"role"`
	Avatar   string `json:"avatar"`
}

type DashboardData struct {
	Metrics    []Metric    `json:"metrics"`
	Chart      ChartData   `json:"chart"`
	Activities []Activity  `json:"activities"`
	Systems    []SysStatus `json:"systems"`
}

type Metric struct {
	Label  string  `json:"label"`
	Value  string  `json:"value"`
	Change float64 `json:"change"`
	Icon   string  `json:"icon"`
}

type ChartData struct {
	Labels []string  `json:"labels"`
	Values []float64 `json:"values"`
}

type Activity struct {
	ID        string `json:"id"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"` // info, success, warning, error
}

type SysStatus struct {
	Name   string  `json:"name"`
	Status string  `json:"status"` // healthy, degraded, down
	Uptime float64 `json:"uptime"`
}

// ── Fake user store (replace with DB in production) ──────────────────────────

var users = map[string]struct {
	Password string
	User     User
}{
	"admin": {
		Password: "admin123",
		User: User{
			ID: "usr_001", Username: "admin",
			Name: "Ana Silva", Role: "Administrador",
			Avatar: "AS",
		},
	},
	"viewer": {
		Password: "viewer123",
		User: User{
			ID: "usr_002", Username: "viewer",
			Name: "Carlos Mendes", Role: "Visualizador",
			Avatar: "CM",
		},
	},
}

// ── JWT helpers ──────────────────────────────────────────────────────────────

func generateToken(user User) (string, int64, error) {
	exp := time.Now().Add(24 * time.Hour)
	claims := jwt.MapClaims{
		"sub":      user.ID,
		"username": user.Username,
		"name":     user.Name,
		"role":     user.Role,
		"exp":      exp.Unix(),
		"iat":      time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtSecret)
	return signed, exp.Unix(), err
}

func parseToken(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, jwt.ErrSignatureInvalid
}

// ── Middleware ────────────────────────────────────────────────────────────────

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" || !strings.HasPrefix(header, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token não fornecido"})
			return
		}
		claims, err := parseToken(strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token inválido ou expirado"})
			return
		}
		c.Set("claims", claims)
		c.Next()
	}
}

// ── Handlers ─────────────────────────────────────────────────────────────────

func handleLogin(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Campos obrigatórios: username, password"})
		return
	}

	stored, exists := users[req.Username]
	if !exists || stored.Password != req.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Credenciais inválidas"})
		return
	}

	token, exp, err := generateToken(stored.User)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Erro ao gerar token"})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		Token:     token,
		ExpiresAt: exp,
		User:      stored.User,
	})
}

func handleDashboard(c *gin.Context) {
	data := DashboardData{
		Metrics: []Metric{
			{Label: "Usuários Ativos", Value: "12.847", Change: 12.5, Icon: "users"},
			{Label: "Requisições/min", Value: "8.432", Change: -3.2, Icon: "activity"},
			{Label: "Uptime", Value: "99.97%", Change: 0.02, Icon: "server"},
			{Label: "Latência Média", Value: "42ms", Change: -8.1, Icon: "clock"},
		},
		Chart: ChartData{
			Labels: []string{"00h", "04h", "08h", "12h", "16h", "20h", "24h"},
			Values: []float64{1200, 800, 2400, 5800, 7200, 6100, 3400},
		},
		Activities: []Activity{
			{ID: "evt_1", Message: "Deploy v2.4.1 realizado com sucesso", Timestamp: "2 min atrás", Type: "success"},
			{ID: "evt_2", Message: "Pico de CPU detectado no pod backend-7f8d", Timestamp: "15 min atrás", Type: "warning"},
			{ID: "evt_3", Message: "Novo usuário registrado: maria@empresa.com", Timestamp: "32 min atrás", Type: "info"},
			{ID: "evt_4", Message: "Certificado SSL renovado automaticamente", Timestamp: "1h atrás", Type: "success"},
			{ID: "evt_5", Message: "Rate limit atingido no endpoint /api/search", Timestamp: "2h atrás", Type: "error"},
			{ID: "evt_6", Message: "Backup diário concluído (23.4 GB)", Timestamp: "3h atrás", Type: "info"},
		},
		Systems: []SysStatus{
			{Name: "API Gateway", Status: "healthy", Uptime: 99.99},
			{Name: "PostgreSQL", Status: "healthy", Uptime: 99.95},
			{Name: "Redis Cache", Status: "healthy", Uptime: 100.0},
			{Name: "Worker Queue", Status: "degraded", Uptime: 98.70},
			{Name: "Storage (S3)", Status: "healthy", Uptime: 99.99},
		},
	}
	c.JSON(http.StatusOK, data)
}

func handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"version": "1.0.0",
		"time":    time.Now().UTC().Format(time.RFC3339),
	})
}

func handleMe(c *gin.Context) {
	claims := c.MustGet("claims").(jwt.MapClaims)
	c.JSON(http.StatusOK, gin.H{
		"id":       claims["sub"],
		"username": claims["username"],
		"name":     claims["name"],
		"role":     claims["role"],
	})
}

// ── Main ─────────────────────────────────────────────────────────────────────

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	allowedOrigins := os.Getenv("CORS_ORIGINS")
	if allowedOrigins == "" {
		allowedOrigins = "http://localhost:3000,http://localhost:8081"
	}

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     strings.Split(allowedOrigins, ","),
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Public routes
	r.POST("/api/auth/login", handleLogin)
	r.GET("/api/health", handleHealth)

	// Protected routes
	protected := r.Group("/api")
	protected.Use(authMiddleware())
	{
		protected.GET("/me", handleMe)
		protected.GET("/dashboard", handleDashboard)
	}

	log.Printf("🚀 Backend listening on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatal(err)
	}
}
