require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
// const { BlobServiceClient } = require("@azure/storage-blob");
const { Server } = require("socket.io");
const { useAzureSocketIO } = require("@azure/web-pubsub-socket.io");

const { getPool, sql } = require("./db");
const authMiddleware = require("./authMiddleware");

const app = express();
const port = Number(process.env.PORT || 5001);

app.use(cors({
    origin: process.env.CLIENT_ORIGIN,
    credentials: true
}));
app.use(express.json());

const upload = multer({ storage: multer.memoryStorage() });

// const blobServiceClient = BlobServiceClient.fromConnectionString(
//     process.env.AZURE_STORAGE_CONNECTION_STRING
// );
// const containerClient = blobServiceClient.getContainerClient(
//     process.env.AZURE_STORAGE_CONTAINER
// );

// async function ensureContainer() {
//     await containerClient.createIfNotExists();
// }

function createToken(user) {
    return jwt.sign(
        {
            id: user.id,
            username: user.username,
            email: user.email
        },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
    );
}

// -------------------- AUTH --------------------

app.post("/api/auth/register", async (req, res) => {
    try {
        const { username, email, password } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ message: "All fields are required." });
        }

        const pool = await getPool();

        const existing = await pool.request()
            .input("email", sql.NVarChar, email)
            .input("username", sql.NVarChar, username)
            .query(`
        SELECT TOP 1 Id
        FROM Users
        WHERE Email = @email OR Username = @username
      `);

        if (existing.recordset.length > 0) {
            return res.status(409).json({ message: "User already exists." });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const result = await pool.request()
            .input("username", sql.NVarChar, username)
            .input("email", sql.NVarChar, email)
            .input("passwordHash", sql.NVarChar, passwordHash)
            .query(`
        INSERT INTO Users (Username, Email, PasswordHash)
        OUTPUT INSERTED.Id, INSERTED.Username, INSERTED.Email
        VALUES (@username, @email, @passwordHash)
      `);

        const newUser = result.recordset[0];

        const token = createToken({
            id: newUser.Id,
            username: newUser.Username,
            email: newUser.Email
        });

        res.status(201).json({
            token,
            user: {
                id: newUser.Id,
                username: newUser.Username,
                email: newUser.Email
            }
        });
    } catch (error) {
        console.error("Register error:", error);
        res.status(500).json({ message: "Server error." });
    }
});

app.post("/api/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const pool = await getPool();
        const result = await pool.request()
            .input("email", sql.NVarChar, email)
            .query(`
        SELECT TOP 1 Id, Username, Email, PasswordHash
        FROM Users
        WHERE Email = @email
      `);

        if (result.recordset.length === 0) {
            return res.status(401).json({ message: "Invalid credentials." });
        }

        const user = result.recordset[0];
        const passwordOk = await bcrypt.compare(password, user.PasswordHash);

        if (!passwordOk) {
            return res.status(401).json({ message: "Invalid credentials." });
        }

        const token = createToken({
            id: user.Id,
            username: user.Username,
            email: user.Email
        });

        res.json({
            token,
            user: {
                id: user.Id,
                username: user.Username,
                email: user.Email
            }
        });
    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Server error." });
    }
});

app.get("/api/auth/me", authMiddleware, async (req, res) => {
    res.json({ user: req.user });
});

// -------------------- ROOMS --------------------

app.get("/api/rooms", authMiddleware, async (req, res) => {
    try {
        const pool = await getPool();
        const result = await pool.request().query(`
      SELECT Id, Name, CreatedAt
      FROM ChatRooms
      ORDER BY Name
    `);

        res.json(result.recordset);
    } catch (error) {
        console.error("Rooms error:", error);
        res.status(500).json({ message: "Server error." });
    }
});

app.post("/api/rooms", authMiddleware, async (req, res) => {
    try {
        const { name } = req.body;

        if (!name || !name.trim()) {
            return res.status(400).json({ message: "Room name is required." });
        }

        const pool = await getPool();
        const result = await pool.request()
            .input("name", sql.NVarChar, name.trim())
            .query(`
        INSERT INTO ChatRooms (Name)
        OUTPUT INSERTED.Id, INSERTED.Name, INSERTED.CreatedAt
        VALUES (@name)
      `);

        res.status(201).json(result.recordset[0]);
    } catch (error) {
        console.error("Create room error:", error);
        res.status(500).json({ message: "Server error." });
    }
});

// -------------------- MESSAGES --------------------

app.get("/api/messages/:roomId", authMiddleware, async (req, res) => {
    try {
        const roomId = Number(req.params.roomId);

        const pool = await getPool();
        const result = await pool.request()
            .input("roomId", sql.Int, roomId)
            .query(`
        SELECT 
          m.Id,
          m.RoomId,
          m.UserId,
          u.Username,
          m.MessageText,
          m.FileUrl,
          m.FileName,
          m.CreatedAt
        FROM Messages m
        INNER JOIN Users u ON m.UserId = u.Id
        WHERE m.RoomId = @roomId
        ORDER BY m.CreatedAt ASC
      `);

        res.json(result.recordset);
    } catch (error) {
        console.error("Get messages error:", error);
        res.status(500).json({ message: "Server error." });
    }
});

app.post("/api/messages/:roomId", authMiddleware, async (req, res) => {
    try {
        const roomId = Number(req.params.roomId);
        const { messageText } = req.body;

        if (!messageText || !messageText.trim()) {
            return res.status(400).json({ message: "Message cannot be empty." });
        }

        const pool = await getPool();
        const result = await pool.request()
            .input("roomId", sql.Int, roomId)
            .input("userId", sql.Int, req.user.id)
            .input("messageText", sql.NVarChar(sql.MAX), messageText.trim())
            .query(`
        INSERT INTO Messages (RoomId, UserId, MessageText)
        OUTPUT INSERTED.Id, INSERTED.RoomId, INSERTED.UserId, INSERTED.MessageText, INSERTED.FileUrl, INSERTED.FileName, INSERTED.CreatedAt
        VALUES (@roomId, @userId, @messageText)
      `);

        const inserted = result.recordset[0];

        const messagePayload = {
            id: inserted.Id,
            roomId: inserted.RoomId,
            userId: inserted.UserId,
            username: req.user.username,
            messageText: inserted.MessageText,
            fileUrl: inserted.FileUrl,
            fileName: inserted.FileName,
            createdAt: inserted.CreatedAt
        };

        io.to(`room-${roomId}`).emit("new-message", messagePayload);

        res.status(201).json(messagePayload);
    } catch (error) {
        console.error("Post message error:", error);
        res.status(500).json({ message: "Server error." });
    }
});

app.post("/api/messages/:roomId/upload", authMiddleware, upload.single("file"), async (req, res) => {
    try {
        const roomId = Number(req.params.roomId);

        if (!req.file) {
            return res.status(400).json({ message: "File is required." });
        }

        // const blobName = `${roomId}/${uuidv4()}-${req.file.originalname}`;
        // const blockBlobClient = containerClient.getBlockBlobClient(blobName);

        await blockBlobClient.uploadData(req.file.buffer, {
            blobHTTPHeaders: {
                blobContentType: req.file.mimetype
            }
        });

        const fileUrl = blockBlobClient.url;

        const pool = await getPool();
        const result = await pool.request()
            .input("roomId", sql.Int, roomId)
            .input("userId", sql.Int, req.user.id)
            .input("fileUrl", sql.NVarChar(1000), fileUrl)
            .input("fileName", sql.NVarChar(255), req.file.originalname)
            .query(`
        INSERT INTO Messages (RoomId, UserId, FileUrl, FileName)
        OUTPUT INSERTED.Id, INSERTED.RoomId, INSERTED.UserId, INSERTED.MessageText, INSERTED.FileUrl, INSERTED.FileName, INSERTED.CreatedAt
        VALUES (@roomId, @userId, @fileUrl, @fileName)
      `);

        const inserted = result.recordset[0];

        const messagePayload = {
            id: inserted.Id,
            roomId: inserted.RoomId,
            userId: inserted.UserId,
            username: req.user.username,
            messageText: inserted.MessageText,
            fileUrl: inserted.FileUrl,
            fileName: inserted.FileName,
            createdAt: inserted.CreatedAt
        };

        io.to(`room-${roomId}`).emit("new-message", messagePayload);

        res.status(201).json(messagePayload);
    } catch (error) {
        console.error("Upload message error:", error);
        res.status(500).json({ message: "Server error." });
    }
});

app.get("/api/socket", async (req, res) => {
    try {
        const { WebPubSubServiceClient } = require("@azure/web-pubsub");

        const serviceClient = new WebPubSubServiceClient(
            process.env.WEB_PUBSUB_CONNECTION_STRING,
            process.env.WEB_PUBSUB_HUB
        );

        const token = await serviceClient.getClientAccessToken();

        res.json({
            url: token.url
        });
    } catch (err) {
        console.error("socket token error:", err);
        res.status(500).json({ message: "socket error" });
    }
});

// -------------------- HEALTH --------------------

app.get("/api/health", async (_req, res) => {
    res.json({ ok: true });
});

// -------------------- SOCKET.IO + AZURE WEB PUBSUB --------------------

// const httpServer = app.listen(port, async () => {
//     try {
//         await ensureContainer();
//         await getPool();
//         console.log(`Backend running on port ${port}`);
//     } catch (error) {
//         console.error("Startup error:", error);
//     }
// });

const httpServer = app.listen(port, () => {
    console.log(`Backend running on port ${port}`);
});

const io = new Server(httpServer, {
    cors: {
        origin: process.env.CLIENT_ORIGIN,
        methods: ["GET", "POST"]
    }
});

useAzureSocketIO(io, {
    hub: process.env.WEB_PUBSUB_HUB,
    connectionString: process.env.WEB_PUBSUB_CONNECTION_STRING
});

io.on("connection", (socket) => {
    socket.on("join-room", (roomId) => {
        socket.join(`room-${roomId}`);
    });

    socket.on("leave-room", (roomId) => {
        socket.leave(`room-${roomId}`);
    });
});