const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const XLSX = require('xlsx');
<<<<<<< HEAD
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, HeadObjectCommand, CreateBucketCommand, ListBucketsCommand } = require('@aws-sdk/client-s3');
=======
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558

const app = express();
const PORT = 3000;

// MinIO Configuration for Windows
const minioConfig = {
  endpoint: 'http://localhost:9000',
  region: 'us-east-1',
  credentials: {
    accessKeyId: 'minioadmin',
    secretAccessKey: 'minioadmin',
  },
  forcePathStyle: true,
  requestHandler: {
    timeout: 10000
  }
};

const s3Client = new S3Client(minioConfig);
const BUCKET_NAME = 'file-organizer';

// Enhanced MinIO initialization with bucket creation
async function initializeBucket() {
  let retries = 3;
  
  while (retries > 0) {
    try {
      console.log(`🔗 Connecting to MinIO (attempt ${4 - retries}/3)...`);
      
      // Test connection by listing buckets
      const listCommand = new ListBucketsCommand({});
      await s3Client.send(listCommand);
      console.log('✅ Connected to MinIO successfully');
      
      // Try to create bucket
      try {
        const createBucketCommand = new CreateBucketCommand({
          Bucket: BUCKET_NAME,
        });
        await s3Client.send(createBucketCommand);
        console.log(`✅ Bucket "${BUCKET_NAME}" created successfully`);
      } catch (createError) {
        if (createError.name === 'BucketAlreadyOwnedByYou') {
          console.log(`✅ Bucket "${BUCKET_NAME}" already exists`);
        } else {
          console.log(`ℹ️ Bucket will be created on first upload`);
        }
      }
      
      return true;
      
    } catch (error) {
      retries--;
      
      if (retries === 0) {
        console.error('❌ Failed to connect to MinIO after 3 attempts');
        console.log('💡 Please ensure MinIO is running:');
        console.log('💡 Run: C:\\minio\\minio.exe server C:\\minio\\data --console-address ":9001"');
        console.log('💡 Then restart this application');
        return false;
      }
      
      console.log(`⚠️ Connection failed, retrying in 3 seconds... (${retries} attempts left)`);
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
  }
}

// Security middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});

app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// Session management
app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Database setup
const db = new sqlite3.Database('./file-organizer.db');

// Initialize database tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        storage_quota INTEGER DEFAULT 1073741824,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        original_name TEXT NOT NULL,
        secure_name TEXT NOT NULL,
        category TEXT NOT NULL,
        size INTEGER NOT NULL,
        mime_type TEXT NOT NULL,
        file_path TEXT NOT NULL,
        uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )`);

    const defaultPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, email, password_hash) VALUES (?, ?, ?)`, 
        ['admin', 'admin@example.com', defaultPassword]);
});

// Storage configuration
const tempDir = path.join(__dirname, 'temp-uploads');
if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
}

// File type validation
const allowedExtensions = {
    images: ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg'],
    videos: ['.mp4', '.avi', '.mov', '.webm', '.mkv'],
    audio: ['.mp3', '.wav', '.ogg', '.aac', '.flac', '.m4a'],
    documents: ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.xls', '.xlsx', '.ppt', '.pptx'],
    json: ['.json']
};

const allowedMimeTypes = {
    images: ['image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp', 'image/svg+xml'],
    videos: ['video/mp4', 'video/avi', 'video/quicktime', 'video/webm', 'video/x-matroska'],
    audio: ['audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/aac', 'audio/flac', 'audio/x-m4a'],
    documents: [
        'application/pdf', 
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'text/plain',
        'application/rtf',
        'application/vnd.ms-excel',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    ],
    json: ['application/json']
};

// Configure multer for temporary uploads
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, tempDir);
    },
    filename: (req, file, cb) => {
        const randomName = crypto.randomBytes(16).toString('hex');
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, `${randomName}${ext}`);
    }
});

const fileFilter = (req, file, cb) => {
    try {
        const ext = path.extname(file.originalname).toLowerCase();
        const isAllowed = Object.values(allowedExtensions).some(extensions => 
            extensions.includes(ext)
        );

        if (!isAllowed) {
            return cb(new Error('File type not allowed'), false);
        }

        const isMimeTypeValid = Object.values(allowedMimeTypes).some(mimeTypes =>
            mimeTypes.includes(file.mimetype)
        );

        if (!isMimeTypeValid) {
            return cb(new Error('MIME type not allowed'), false);
        }

        cb(null, true);
    } catch (error) {
        cb(new Error('File validation error'), false);
    }
};

const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 50 * 1024 * 1024,
        files: 10
    }
});

// File categorization
function getFileCategory(filename, mimetype) {
    const ext = path.extname(filename).toLowerCase();
    
    for (const [category, extensions] of Object.entries(allowedExtensions)) {
        if (extensions.includes(ext)) {
            if (allowedMimeTypes[category].includes(mimetype)) {
                return category;
            }
        }
    }
    return 'others';
}

// Authentication middleware
function requireAuth(req, res, next) {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Authentication required' });
    }
}

// Check user storage quota
function checkStorageQuota(userId) {
    return new Promise((resolve, reject) => {
        db.get(
            `SELECT u.storage_quota, COALESCE(SUM(f.size), 0) as used_storage
             FROM users u 
             LEFT JOIN files f ON u.id = f.user_id 
             WHERE u.id = ? 
             GROUP BY u.id`,
            [userId],
            (err, row) => {
                if (err) reject(err);
                else resolve(row);
            }
        );
    });
}

// Upload file to MinIO with automatic bucket creation
async function uploadToMinIO(filePath, objectKey, mimetype) {
    try {
        const fileBuffer = fs.readFileSync(filePath);
        
        const command = new PutObjectCommand({
            Bucket: BUCKET_NAME,
            Key: objectKey,
            Body: fileBuffer,
            ContentType: mimetype,
            Metadata: {
                'uploaded-at': new Date().toISOString()
            }
        });

        const result = await s3Client.send(command);
        console.log(`✅ File uploaded to MinIO: ${objectKey}`);
        return result;
    } catch (error) {
        if (error.name === 'NoSuchBucket') {
            console.log('📦 Bucket does not exist, trying to create it...');
            try {
                // Create bucket
                const createBucketCommand = new CreateBucketCommand({
                    Bucket: BUCKET_NAME,
                });
                await s3Client.send(createBucketCommand);
                console.log('✅ Bucket created successfully, retrying upload...');
                
                // Retry upload
                const retryCommand = new PutObjectCommand({
                    Bucket: BUCKET_NAME,
                    Key: objectKey,
                    Body: fs.readFileSync(filePath),
                    ContentType: mimetype,
                });
                const result = await s3Client.send(retryCommand);
                console.log(`✅ File uploaded to MinIO after bucket creation: ${objectKey}`);
                return result;
            } catch (createError) {
                console.error('❌ Failed to create bucket:', createError);
                throw new Error('Failed to create storage bucket');
            }
        }
        console.error('❌ MinIO upload error:', error.name, error.message);
        throw new Error(`Failed to upload file: ${error.message}`);
    }
}

// Download file from MinIO
async function downloadFromMinIO(objectKey) {
    try {
        const command = new GetObjectCommand({
            Bucket: BUCKET_NAME,
            Key: objectKey
        });

        const response = await s3Client.send(command);
        return response.Body;
    } catch (error) {
        console.error('❌ MinIO download error:', error.name, error.message);
        throw new Error(`Failed to download file: ${error.message}`);
    }
}

// Delete file from MinIO
async function deleteFromMinIO(objectKey) {
    try {
        const command = new DeleteObjectCommand({
            Bucket: BUCKET_NAME,
            Key: objectKey
        });

        await s3Client.send(command);
        console.log(`✅ File deleted from MinIO: ${objectKey}`);
        return true;
    } catch (error) {
        console.error('❌ MinIO delete error:', error.name, error.message);
        throw new Error(`Failed to delete file: ${error.message}`);
    }
}

// Check if file exists in MinIO
async function fileExistsInMinIO(objectKey) {
    try {
        const command = new HeadObjectCommand({
            Bucket: BUCKET_NAME,
            Key: objectKey
        });

        await s3Client.send(command);
        return true;
    } catch (error) {
        if (error.name === 'NotFound') {
            return false;
        }
        throw error;
    }
}

// Secure file organization for user with MinIO
async function organizeFileForUser(userId, sourcePath, originalName, mimetype) {
    const category = getFileCategory(originalName, mimetype);
    
    const fileExt = path.extname(originalName).toLowerCase();
    const secureFilename = crypto.randomBytes(16).toString('hex') + fileExt;
    const objectKey = `user_${userId}/${category}/${secureFilename}`;

    try {
        await uploadToMinIO(sourcePath, objectKey, mimetype);
        
        const exists = await fileExistsInMinIO(objectKey);
        if (!exists) {
            throw new Error('File upload verification failed');
        }

        const stats = fs.statSync(sourcePath);

        return {
            originalName: originalName,
            secureName: secureFilename,
            category: category,
            size: stats.size,
            filePath: objectKey
        };
    } catch (error) {
        throw new Error(`Cloud storage error: ${error.message}`);
    } finally {
        cleanupTempFile(sourcePath);
    }
}

function cleanupTempFile(filePath) {
    try {
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }
    } catch (error) {
        console.error('Error cleaning up temp file:', error);
    }
}

// Clean up old temporary files
function cleanupOldTempFiles() {
    try {
        const files = fs.readdirSync(tempDir);
        const now = Date.now();
        const maxAge = 30 * 60 * 1000;

        files.forEach(file => {
            const filePath = path.join(tempDir, file);
            try {
                const stats = fs.statSync(filePath);
                if (now - stats.mtime.getTime() > maxAge) {
                    fs.unlinkSync(filePath);
                }
            } catch (error) {
                console.error('Error cleaning up file:', error);
            }
        });
    } catch (error) {
        console.error('Error during temp file cleanup:', error);
    }
}

setInterval(cleanupOldTempFiles, 30 * 60 * 1000);

// Helper function to check if file is previewable
function isPreviewable(mimeType) {
    const previewableTypes = [
        'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp', 'image/svg+xml',
        'video/mp4', 'video/avi', 'video/quicktime', 'video/webm', 'video/x-matroska',
        'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/aac', 'audio/flac', 'audio/x-m4a',
        'application/pdf'
    ];
    return previewableTypes.includes(mimeType);
}

// Enhanced JSON parsing with error recovery
function parseJsonSafely(jsonString) {
    try {
<<<<<<< HEAD
=======
        // First try to parse directly
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
        return JSON.parse(jsonString);
    } catch (error) {
        console.log('Direct parsing failed, trying to clean JSON...');
        
<<<<<<< HEAD
        let cleaned = jsonString.replace(/^[^{[]*/, '');
        cleaned = cleaned.replace(/[^}\]]*$/, '');
        
=======
        // Try to extract JSON from the string
        // Remove any content before the first { or [
        let cleaned = jsonString.replace(/^[^{[]*/, '');
        
        // Remove any content after the last } or ]
        cleaned = cleaned.replace(/[^}\]]*$/, '');
        
        // Try to parse the cleaned version
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
        try {
            return JSON.parse(cleaned);
        } catch (secondError) {
            console.log('Cleaned parsing failed, trying line by line...');
            
<<<<<<< HEAD
=======
            // Try to find valid JSON lines
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
            const lines = jsonString.split('\n');
            const validLines = lines.filter(line => {
                const trimmed = line.trim();
                return trimmed.length > 0 && 
                       (trimmed.startsWith('{') || trimmed.startsWith('[') ||
                        trimmed.startsWith('"') || /^\d/.test(trimmed) ||
                        trimmed === 'true' || trimmed === 'false' || trimmed === 'null');
            });
            
            if (validLines.length > 0) {
                try {
<<<<<<< HEAD
=======
                    // Try to parse as array of JSON objects
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
                    const jsonArray = validLines.map(line => {
                        try {
                            return JSON.parse(line.trim());
                        } catch (e) {
                            return line.trim();
                        }
                    });
                    return jsonArray;
                } catch (thirdError) {
<<<<<<< HEAD
=======
                    // Last resort: return as plain text with error info
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
                    return {
                        error: 'Could not parse as valid JSON',
                        original_length: jsonString.length,
                        sample: jsonString.substring(0, 200) + '...',
                        cleaned_data: validLines.slice(0, 10)
                    };
                }
            }
            
<<<<<<< HEAD
            throw new Error(`JSON parsing failed: ${error.message}`);
=======
            throw new Error(`JSON parsing failed: ${error.message}. Also failed cleaned parsing: ${secondError.message}`);
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
        }
    }
}

function convertJsonToExcel(data) {
    try {
        const workbook = XLSX.utils.book_new();
        
        if (Array.isArray(data)) {
            if (data.length === 0) {
<<<<<<< HEAD
=======
                // Create empty worksheet with message
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
                const worksheet = XLSX.utils.aoa_to_sheet([['No data available']]);
                XLSX.utils.book_append_sheet(workbook, worksheet, 'Data');
            } else {
                const worksheet = XLSX.utils.json_to_sheet(data);
                XLSX.utils.book_append_sheet(workbook, worksheet, 'Data');
            }
        } else if (typeof data === 'object' && data !== null) {
<<<<<<< HEAD
=======
            // Convert object to array of key-value pairs
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
            const rows = Object.entries(data).map(([key, value]) => ({
                Key: key,
                Value: typeof value === 'object' ? JSON.stringify(value) : value
            }));
            const worksheet = XLSX.utils.json_to_sheet(rows);
            XLSX.utils.book_append_sheet(workbook, worksheet, 'Data');
        } else {
<<<<<<< HEAD
=======
            // Handle primitive values
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
            const worksheet = XLSX.utils.aoa_to_sheet([['Value'], [data]]);
            XLSX.utils.book_append_sheet(workbook, worksheet, 'Data');
        }
        
        return workbook;
    } catch (error) {
        console.error('Excel conversion error:', error);
<<<<<<< HEAD
=======
        // Create error worksheet
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
        const workbook = XLSX.utils.book_new();
        const worksheet = XLSX.utils.aoa_to_sheet([
            ['Error during Excel conversion'],
            ['Message', error.message],
            ['Please check your JSON file format']
        ]);
        XLSX.utils.book_append_sheet(workbook, worksheet, 'Error');
        return workbook;
    }
}

function getJsonPreview(data, maxRows = 10) {
    if (Array.isArray(data)) {
        return {
            type: 'array',
            count: data.length,
            preview: data.slice(0, maxRows),
            keys: data.length > 0 && data[0] ? Object.keys(data[0]) : []
        };
    } else if (typeof data === 'object' && data !== null) {
        return {
            type: 'object',
            keys: Object.keys(data),
            preview: data
        };
    } else {
        return {
            type: 'primitive',
            value: data
        };
    }
}

function analyzeJsonStructure(data) {
    const structure = {
        type: Array.isArray(data) ? 'array' : typeof data,
        size: Array.isArray(data) ? data.length : 'n/a'
    };
    
    if (Array.isArray(data) && data.length > 0 && data[0]) {
        structure.sampleKeys = Object.keys(data[0]);
        structure.sampleTypes = {};
        
        const firstItem = data[0];
        for (const key in firstItem) {
            structure.sampleTypes[key] = typeof firstItem[key];
        }
    } else if (typeof data === 'object' && data !== null) {
        structure.keys = Object.keys(data);
        structure.valueTypes = {};
        
        for (const key in data) {
            structure.valueTypes[key] = typeof data[key];
        }
    }
    
    return structure;
}

// Authentication Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        
        db.run(
            `INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)`,
            [username, email, passwordHash],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ error: 'Username or email already exists' });
                    }
                    return res.status(500).json({ error: 'Registration failed' });
                }
                
                console.log(`👤 Created user: ${username} (ID: ${this.lastID})`);
                res.json({ message: 'User registered successfully' });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        db.get(
            `SELECT id, username, password_hash FROM users WHERE username = ?`,
            [username],
            async (err, user) => {
                if (err) {
                    return res.status(500).json({ error: 'Login failed' });
                }
                
                if (!user) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                const isValidPassword = await bcrypt.compare(password, user.password_hash);
                
                if (!isValidPassword) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                req.session.userId = user.id;
                req.session.username = user.username;
                
                res.json({ 
                    message: 'Login successful',
                    user: { id: user.id, username: user.username }
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ message: 'Logout successful' });
    });
});

app.get('/api/user', requireAuth, (req, res) => {
    db.get(
        `SELECT u.id, u.username, u.email, u.storage_quota, 
                COALESCE(SUM(f.size), 0) as used_storage
         FROM users u 
         LEFT JOIN files f ON u.id = f.user_id 
         WHERE u.id = ? 
         GROUP BY u.id`,
        [req.session.userId],
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to get user data' });
            }
            res.json({ user });
        }
    );
});

// File Routes (protected)
app.post('/api/upload', requireAuth, upload.array('files'), async (req, res) => {
    try {
        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ error: 'No files uploaded' });
        }

        const userId = req.session.userId;
        
        // Check storage quota
        const quotaInfo = await checkStorageQuota(userId);
        const totalSize = req.files.reduce((sum, file) => sum + file.size, 0);
        
        if (quotaInfo.used_storage + totalSize > quotaInfo.storage_quota) {
            req.files.forEach(file => cleanupTempFile(file.path));
            return res.status(400).json({ error: 'Storage quota exceeded' });
        }

        const results = [];
        
        for (const file of req.files) {
            try {
                const fileInfo = await organizeFileForUser(userId, file.path, file.originalname, file.mimetype);
                
                // Save file metadata to database
                db.run(
                    `INSERT INTO files (user_id, original_name, secure_name, category, size, mime_type, file_path) 
                     VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [userId, fileInfo.originalName, fileInfo.secureName, fileInfo.category, 
                     fileInfo.size, file.mimetype, fileInfo.filePath],
                    function(err) {
                        if (err) {
                            console.error('Error saving file metadata:', err);
                        }
                    }
                );

                results.push({
                    originalName: fileInfo.originalName,
                    secureName: fileInfo.secureName,
                    category: fileInfo.category,
                    size: fileInfo.size,
                    status: 'organized'
                });
            } catch (error) {
                results.push({
                    originalName: file.originalname,
                    error: error.message,
                    status: 'failed'
                });
            }
        }

        res.json({
            message: 'Files organized successfully',
            results: results
        });
    } catch (error) {
        res.status(500).json({ error: 'Upload processing failed' });
    }
});

app.get('/api/files', requireAuth, (req, res) => {
    const userId = req.session.userId;
    
    db.all(
        `SELECT id, original_name, secure_name, category, size, mime_type, uploaded_at
         FROM files 
         WHERE user_id = ? 
         ORDER BY category, uploaded_at DESC`,
        [userId],
        (err, files) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to retrieve files' });
            }

            const filesByCategory = {};
            files.forEach(file => {
                if (!filesByCategory[file.category]) {
                    filesByCategory[file.category] = [];
                }
                filesByCategory[file.category].push({
                    id: file.id,
                    name: file.secure_name,
                    displayName: file.original_name,
                    size: file.size,
                    mimeType: file.mime_type,
                    uploaded: file.uploaded_at,
                    category: file.category
                });
            });

            res.json(filesByCategory);
        }
    );
});

// File download and preview routes
app.get('/api/files/:fileId/download', requireAuth, async (req, res) => {
    const userId = req.session.userId;
    const fileId = req.params.fileId;
    
    db.get(
        `SELECT original_name, file_path, mime_type FROM files WHERE id = ? AND user_id = ?`,
        [fileId, userId],
        async (err, file) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (!file) {
                return res.status(404).json({ error: 'File not found' });
            }

            try {
                const exists = await fileExistsInMinIO(file.file_path);
                if (!exists) {
                    return res.status(404).json({ error: 'File not found in cloud storage' });
                }

                res.setHeader('Content-Disposition', `attachment; filename="${file.original_name}"`);
                res.setHeader('Content-Type', file.mime_type);
                
                const fileStream = await downloadFromMinIO(file.file_path);
                const chunks = [];
                for await (const chunk of fileStream) {
                    chunks.push(chunk);
                }
                const buffer = Buffer.concat(chunks);
                
                res.send(buffer);
            } catch (error) {
                console.error('Download error:', error);
                res.status(500).json({ error: 'Error downloading file from cloud storage' });
            }
        }
    );
});

app.get('/api/files/:fileId/preview', requireAuth, async (req, res) => {
    const userId = req.session.userId;
    const fileId = req.params.fileId;
    
    db.get(
        `SELECT original_name, file_path, mime_type FROM files WHERE id = ? AND user_id = ?`,
        [fileId, userId],
        async (err, file) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (!file) {
                return res.status(404).json({ error: 'File not found' });
            }

            if (!isPreviewable(file.mime_type)) {
                return res.status(400).json({ error: 'File type not previewable' });
            }

            try {
                const exists = await fileExistsInMinIO(file.file_path);
                if (!exists) {
                    return res.status(404).json({ error: 'File not found in cloud storage' });
                }

                res.setHeader('Content-Type', file.mime_type);
                res.setHeader('Content-Disposition', `inline; filename="${file.original_name}"`);
                
                const fileStream = await downloadFromMinIO(file.file_path);
                const chunks = [];
                for await (const chunk of fileStream) {
                    chunks.push(chunk);
                }
                const buffer = Buffer.concat(chunks);
                
                res.send(buffer);
            } catch (error) {
                console.error('Preview error:', error);
                res.status(500).json({ error: 'Error streaming file from cloud storage' });
            }
        }
    );
});

// Get file info for preview modal
app.get('/api/files/:fileId/info', requireAuth, (req, res) => {
    const userId = req.session.userId;
    const fileId = req.params.fileId;
    
    db.get(
        `SELECT id, original_name, secure_name, category, size, mime_type, uploaded_at 
         FROM files WHERE id = ? AND user_id = ?`,
        [fileId, userId],
        (err, file) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (!file) {
                return res.status(404).json({ error: 'File not found' });
            }

            res.json({
                id: file.id,
                name: file.original_name,
                secureName: file.secure_name,
                category: file.category,
                size: file.size,
                mimeType: file.mime_type,
                uploaded: file.uploaded_at,
                previewable: isPreviewable(file.mime_type)
            });
        }
    );
});

// JSON to Excel conversion endpoint
<<<<<<< HEAD
app.get('/api/files/:fileId/parse-json', requireAuth, async (req, res) => {
=======
app.get('/api/files/:fileId/parse-json', requireAuth, (req, res) => {
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
    const userId = req.session.userId;
    const fileId = req.params.fileId;
    
    console.log(`JSON parse request - User: ${userId}, File: ${fileId}`);
    
    db.get(
        `SELECT file_path, original_name FROM files WHERE id = ? AND user_id = ? AND category = 'json'`,
        [fileId, userId],
<<<<<<< HEAD
        async (err, file) => {
=======
        (err, file) => {
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (!file) {
                console.error('File not found or not JSON');
                return res.status(404).json({ error: 'JSON file not found' });
            }

<<<<<<< HEAD
            try {
                const exists = await fileExistsInMinIO(file.file_path);
                if (!exists) {
                    console.error('File not found in MinIO:', file.file_path);
                    return res.status(404).json({ error: 'File not found in cloud storage' });
                }

                const fileStream = await downloadFromMinIO(file.file_path);
                const chunks = [];
                for await (const chunk of fileStream) {
                    chunks.push(chunk);
                }
                const jsonData = Buffer.concat(chunks).toString('utf8');
                
                console.log('File read successfully from MinIO, size:', jsonData.length);
=======
            console.log('Found file:', file.original_name, 'Path:', file.file_path);

            try {
                // Check if file exists
                if (!fs.existsSync(file.file_path)) {
                    console.error('Physical file not found:', file.file_path);
                    return res.status(404).json({ error: 'File not found on server' });
                }

                // Read and parse JSON file with error recovery
                const jsonData = fs.readFileSync(file.file_path, 'utf8');
                console.log('File read successfully, size:', jsonData.length);
                console.log('First 200 chars:', jsonData.substring(0, 200));
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
                
                const parsedData = parseJsonSafely(jsonData);
                console.log('JSON parsed successfully, type:', typeof parsedData);
                
<<<<<<< HEAD
=======
                // Convert to Excel format
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
                const workbook = convertJsonToExcel(parsedData);
                const fileName = path.parse(file.original_name).name + '.xlsx';
                
                console.log('Excel conversion successful');
                
                res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
                res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
                
                const buffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' });
                res.send(buffer);
            } catch (error) {
                console.error('JSON parsing error:', error);
                res.status(400).json({ error: 'Failed to parse JSON file: ' + error.message });
            }
        }
    );
});

// Get JSON preview data
<<<<<<< HEAD
app.get('/api/files/:fileId/json-preview', requireAuth, async (req, res) => {
=======
app.get('/api/files/:fileId/json-preview', requireAuth, (req, res) => {
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
    const userId = req.session.userId;
    const fileId = req.params.fileId;
    
    console.log(`JSON preview request - User: ${userId}, File: ${fileId}`);
    
    db.get(
        `SELECT file_path, original_name FROM files WHERE id = ? AND user_id = ? AND category = 'json'`,
        [fileId, userId],
<<<<<<< HEAD
        async (err, file) => {
=======
        (err, file) => {
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (!file) {
                console.error('File not found or not JSON');
                return res.status(404).json({ error: 'JSON file not found' });
            }

            try {
<<<<<<< HEAD
                const exists = await fileExistsInMinIO(file.file_path);
                if (!exists) {
                    console.error('File not found in MinIO:', file.file_path);
                    return res.status(404).json({ error: 'File not found in cloud storage' });
                }

                const fileStream = await downloadFromMinIO(file.file_path);
                const chunks = [];
                for await (const chunk of fileStream) {
                    chunks.push(chunk);
                }
                const jsonData = Buffer.concat(chunks).toString('utf8');
=======
                // Check if file exists
                if (!fs.existsSync(file.file_path)) {
                    console.error('Physical file not found:', file.file_path);
                    return res.status(404).json({ error: 'File not found on server' });
                }

                const jsonData = fs.readFileSync(file.file_path, 'utf8');
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
                const parsedData = parseJsonSafely(jsonData);
                
                console.log('JSON preview generated successfully');
                
<<<<<<< HEAD
=======
                // Return preview info
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
                res.json({
                    fileName: file.original_name,
                    data: getJsonPreview(parsedData),
                    structure: analyzeJsonStructure(parsedData),
<<<<<<< HEAD
                    rawSample: jsonData.substring(0, 500)
=======
                    rawSample: jsonData.substring(0, 500) // Include sample for debugging
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
                });
            } catch (error) {
                console.error('JSON preview error:', error);
                res.status(400).json({ 
                    error: 'Failed to parse JSON file: ' + error.message,
<<<<<<< HEAD
                    rawSample: 'Unable to load file sample'
=======
                    rawSample: fs.readFileSync(file.file_path, 'utf8').substring(0, 500)
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
                });
            }
        }
    );
});

<<<<<<< HEAD
app.delete('/api/files/:fileId', requireAuth, async (req, res) => {
=======
app.delete('/api/files/:fileId', requireAuth, (req, res) => {
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
    const userId = req.session.userId;
    const fileId = req.params.fileId;
    
    db.get(
        `SELECT file_path FROM files WHERE id = ? AND user_id = ?`,
        [fileId, userId],
        async (err, file) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            
            if (!file) {
                return res.status(404).json({ error: 'File not found' });
            }

            try {
                await deleteFromMinIO(file.file_path);
                
                db.run(
                    `DELETE FROM files WHERE id = ? AND user_id = ?`,
                    [fileId, userId],
                    function(err) {
                        if (err) {
                            return res.status(500).json({ error: 'Failed to delete file record' });
                        }
                        res.json({ message: 'File deleted successfully' });
                    }
                );
            } catch (error) {
                console.error('Delete error:', error);
                res.status(500).json({ error: 'Failed to delete file from cloud storage' });
            }
        }
    );
});

app.get('/api/stats', requireAuth, (req, res) => {
    const userId = req.session.userId;
    
    db.all(
        `SELECT category, COUNT(*) as count, SUM(size) as size
         FROM files 
         WHERE user_id = ? 
         GROUP BY category`,
        [userId],
        (err, categoryStats) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to retrieve statistics' });
            }

            const stats = {};
            let totalFiles = 0;
            let totalSize = 0;

            categoryStats.forEach(stat => {
                stats[stat.category] = {
                    count: stat.count,
                    size: stat.size
                };
                totalFiles += stat.count;
                totalSize += stat.size;
            });

            stats.total = {
                files: totalFiles,
                size: totalSize
            };

            res.json(stats);
        }
    );
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
    try {
        const listCommand = new ListBucketsCommand({});
        await s3Client.send(listCommand);
        res.json({ 
            status: 'healthy',
            minio: 'connected',
            bucket: BUCKET_NAME
        });
    } catch (error) {
        res.status(503).json({ 
            status: 'unhealthy',
            minio: 'disconnected',
            error: error.message
        });
    }
});

// Serve the main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling
app.use((error, req, res, next) => {
    console.error('Error:', error);
    
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large' });
        }
        if (error.code === 'LIMIT_FILE_COUNT') {
            return res.status(400).json({ error: 'Too many files' });
        }
    }
    
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

<<<<<<< HEAD
// Initialize and start server
initializeBucket().then((minioConnected) => {
    if (!minioConnected) {
        console.log('\n⚠️  WARNING: MinIO is not connected!');
        console.log('💡 Please start MinIO first, then refresh the application');
        console.log('💡 Run this command in a new terminal:');
        console.log('💡 C:\\minio\\minio.exe server C:\\minio\\data --console-address ":9001"');
    }
    
    app.listen(PORT, () => {
        console.log(`\n🚀 File Organizer Server running on http://localhost:${PORT}`);
        console.log(`☁️  Cloud Storage: MinIO ${minioConnected ? '✅ Connected' : '❌ Disconnected'}`);
        console.log(`📦 Storage Bucket: ${BUCKET_NAME}`);
        console.log(`📊 Database: file-organizer.db`);
        console.log(`👤 Default admin: username="admin", password="admin123"`);
        
        if (!minioConnected) {
            console.log(`\n🔴 UPLOADS WILL FAIL until MinIO is started!`);
        } else {
            console.log(`\n✅ Ready for file uploads!`);
        }
    });
}).catch(error => {
    console.error('❌ Failed to initialize application:', error);
});
=======
app.listen(PORT, () => {
    console.log(`🚀 Multi-user File Organizer Server running on http://localhost:${PORT}`);
    console.log(`📁 User storage located in: ${baseDir}`);
    console.log(`📊 Database: file-organizer.db`);
    console.log(`👤 Default admin: username="admin", password="admin123"`);
});
>>>>>>> de04a55fbbee5ce77c3ed413b94725fd028d5558
