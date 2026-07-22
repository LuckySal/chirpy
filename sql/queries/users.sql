-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: ResetUsers :exec
DELETE FROM users;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users
WHERE email = $1;

-- name: GetUserFromRefreshToken :one
SELECT users.id, refresh_tokens.expires_at, refresh_tokens.revoked_at FROM users
JOIN refresh_tokens
    ON users.id = refresh_tokens.user_id
WHERE refresh_tokens.token = $1;

-- name: UpdateUserInfo :one
UPDATE users
SET email = $2, hashed_password = $3, updated_at = NOW()
WHERE id = $1
RETURNING *;

-- name: SetUserRed :exec
UPDATE users
SET is_chirpy_red = true, updated_at = NOW()
WHERE id = $1;