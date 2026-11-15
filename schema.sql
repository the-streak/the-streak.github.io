CREATE TABLE IF NOT EXISTS users(
  id SERIAL PRIMARY KEY,
  username VARCHAR(20) UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  is_admin BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS streaks(
  user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  streak INT NOT NULL DEFAULT 0,
  last_day TEXT,
  best INT NOT NULL DEFAULT 0,
  fusion BOOLEAN NOT NULL DEFAULT false,
  unl BOOLEAN NOT NULL DEFAULT false,
  pin INT
);

-- Nếu bạn đã tạo bảng từ bản trước, chạy thêm 2 dòng này (an toàn khi chạy lại):
ALTER TABLE streaks ADD COLUMN IF NOT EXISTS done_day TEXT;
ALTER TABLE streaks ADD COLUMN IF NOT EXISTS quest INT NOT NULL DEFAULT 0;
