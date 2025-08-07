import express, { Express, Request, Response, NextFunction } from 'express';
import { createServer } from 'node:http';
import { Server } from 'socket.io';
import cors from 'cors';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { Database } from 'sqlite3';

interface User {
  id: number;
  username: string;
  email: string;
  password: string;
  created_at: string;
}

interface Message {
  id: number;
  user_id: number;
  content: string;
  created_at: string;
  username?: string;
}

interface CustomError extends Error {
  status?: number;
}

async function initializeDB() {
  try {
    const db = await open({
      filename: './messages.db',
      driver: sqlite3.Database
    });

    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
      );
    `);

    return db;
  } catch (error) {
    console.error('Database initialization error:', error);
    throw error;
  }
}

async function main() {
  const db = await initializeDB();
  const app: Express = express();
  const httpServer = createServer(app);
  const io = new Server(httpServer, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"]
    }
  });

  app.use(cors());
  app.use(express.json());

  io.on('connection', (socket) => {
    console.log('User connected');

    socket.on('sendMessage', async (data) => {
      try {
        const { user_id, content } = data;

        await db.run(
          'INSERT INTO messages (user_id, content) VALUES (?, ?)',
          [user_id, content]
        );

        const message = await db.get<Message & { username: string }>(`
          SELECT m.*, u.username 
          FROM messages m
          JOIN users u ON m.user_id = u.id
          ORDER BY m.id DESC
          LIMIT 1
        `);

        io.emit('newMessage', message);
      } catch (err) {
        const error = err as Error;
        console.error('Message sending error:', error);
        socket.emit('error', { message: 'Failed to send message' });
      }
    });

    socket.on('disconnect', () => {
      console.log('User disconnected');
    });
  });

  app.get('/api/messages', async (req: Request, res: Response) => {
    try {
      const messages = await db.all<Array<Message & { username: string }>>(`
        SELECT m.*, u.username 
        FROM messages m
        JOIN users u ON m.user_id = u.id
        ORDER BY m.created_at DESC
        LIMIT 50
      `);
      res.json(messages);
    } catch (err) {
      const error = err as Error;
      console.error('Error fetching messages:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.post('/api/register', async (req: Request, res: Response) => {
    try {
      const { username, email, password } = req.body;

      if (!username || !email || !password) {
        return res.status(400).json({ error: 'Missing required fields' });
      }

      // ⚠️ No hashing here
      const result = await db.run(
        'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
        [username, email, password]
      );

      res.status(201).json({
        id: result.lastID,
        username,
        email
      });
    } catch (err) {
      const error = err as Error;
      console.error('Registration error:', error);
      if (error.message.includes('UNIQUE constraint failed')) {
        return res.status(400).json({ error: 'Username or email already exists' });
      }
      res.status(500).json({ error: 'Registration failed' });
    }
  });

  app.post('/api/login', async (req: Request, res: Response) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(400).json({ error: 'Missing required fields' });
      }

      const user = await db.get<User>('SELECT * FROM users WHERE email = ?', [email]);

      // ⚠️ Compare plain text passwords
      if (!user || password !== user.password) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const { password: _, ...userWithoutPassword } = user;
      res.json(userWithoutPassword);
    } catch (err) {
      const error = err as Error;
      console.error('Login error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.get('/api/me', async (req: Request, res: Response) => {
    try {
      const userId = req.headers['user-id'] as string;
      if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
      }

      const user = await db.get<Pick<User, 'id' | 'username' | 'email'>>(
        'SELECT id, username, email FROM users WHERE id = ?',
        [userId]
      );

      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json(user);
    } catch (err) {
      const error = err as Error;
      console.error('Session check error:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  app.use((err: CustomError, req: Request, res: Response, next: NextFunction) => {
    console.error(err.stack);
    res.status(err.status || 500).json({ error: err.message || 'Internal Server Error' });
  });

  const PORT = process.env.PORT || 4000;
  httpServer.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

main().catch((err: Error) => {
  console.error('Server startup error:', err);
  process.exit(1);
});

