# Multi-User File Organizer

A secure, full-featured multi-user file organization system with automatic categorization and preview capabilities. Built with Node.js, Express, and SQLite.

## 🚀 Features

### Core Features
- **Multi-User Support**: Secure user authentication and session management
- **Automatic File Categorization**: Files are automatically organized into categories:
  - Images (jpg, jpeg, png, gif, bmp, webp, svg)
  - Videos (mp4, avi, mov, webm, mkv)
  - Audio (mp3, wav, ogg, aac, flac, m4a)
  - Documents (pdf, doc, docx, txt, rtf, xls, xlsx, ppt, pptx)
  - JSON files
  - Others
- **File Upload & Management**: Secure file uploads with validation
- **File Preview**: In-browser preview for supported file types
- **Storage Quota Management**: Per-user storage limits (1GB default)
- **File Statistics**: Detailed statistics by category and user

### Security Features
- **Secure File Storage**: Files stored with cryptographically secure random names
- **User Isolation**: Each user has their own storage directory
- **File Type Validation**: Both extension and MIME type validation
- **Session Management**: Secure session-based authentication
- **Input Validation**: Comprehensive input validation and sanitization
- **Security Headers**: XSS protection, content type sniffing prevention
- **Password Hashing**: bcrypt password hashing

## 📋 Prerequisites

- Node.js 14.0.0 or higher
- npm (Node Package Manager)

## 🛠️ Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd multi-user-file-organizer
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables (optional)**
   ```bash
   # Create a .env file for custom session secret
   echo "SESSION_SECRET=your-custom-session-secret-here" > .env
   ```

4. **Start the application**
   ```bash
   # Production
   npm start
   
   # Development (with auto-reload)
   npm run dev
   ```

5. **Access the application**
   Open your browser and navigate to `http://localhost:3000`

## 📁 Project Structure

```
multi-user-file-organizer/
├── server.js              # Main application server
├── package.json           # Dependencies and scripts
├── file-organizer.db      # SQLite database (auto-created)
├── user-storage/          # User file storage (auto-created)
│   └── user_<id>/         # Individual user directories
│       ├── images/
│       ├── videos/
│       ├── audio/
│       ├── documents/
│       ├── json/
│       └── others/
├── temp-uploads/          # Temporary upload storage (auto-created)
└── public/                # Static web files (to be created)
    └── index.html         # Main web interface
```

## 🔧 Configuration

### Storage Limits
- **File Size Limit**: 50MB per file
- **Upload Limit**: 10 files per upload
- **User Storage Quota**: 1GB per user (configurable in database)

### Supported File Types
The application supports a wide range of file types organized into categories:

- **Images**: JPEG, PNG, GIF, BMP, WebP, SVG
- **Videos**: MP4, AVI, MOV, WebM, MKV
- **Audio**: MP3, WAV, OGG, AAC, FLAC, M4A
- **Documents**: PDF, DOC, DOCX, TXT, RTF, XLS, XLSX, PPT, PPTX
- **JSON**: JSON files
- **Others**: Any other supported file types

## 🎯 API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - User login
- `POST /api/logout` - User logout
- `GET /api/user` - Get current user info

### File Management
- `POST /api/upload` - Upload files (multipart/form-data)
- `GET /api/files` - Get user's files (grouped by category)
- `GET /api/files/:fileId/download` - Download file
- `GET /api/files/:fileId/preview` - Preview file (supported types)
- `GET /api/files/:fileId/info` - Get file information
- `DELETE /api/files/:fileId` - Delete file

### Statistics
- `GET /api/stats` - Get user's storage statistics

## 👤 Default Admin Account

The application creates a default admin account:
- **Username**: `admin`
- **Password**: `admin123`
- **Email**: `admin@example.com`

> ⚠️ **Security Warning**: Change the default admin password immediately after first login!

## 🔒 Security Considerations

1. **Change Default Credentials**: Update the default admin password
2. **Environment Variables**: Use a custom `SESSION_SECRET` in production
3. **HTTPS**: Deploy behind a reverse proxy with SSL/TLS in production
4. **File Permissions**: Ensure proper file system permissions
5. **Regular Backups**: Back up the SQLite database regularly

## 🚀 Development

### Available Scripts
- `npm start` - Start production server
- `npm run dev` - Start development server with nodemon
- `npm test` - Run tests (Jest)
- `npm run setup` - Run setup script (if available)

### Development Dependencies
- **nodemon**: Auto-restart during development
- **jest**: Testing framework
- **supertest**: HTTP testing

## 🗄️ Database Schema

The application uses SQLite with the following tables:

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    storage_quota INTEGER DEFAULT 1073741824, -- 1GB
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Files Table
```sql
CREATE TABLE files (
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
);
```

## 🛠️ Troubleshooting

### Common Issues

1. **Permission Errors**
   ```bash
   # Fix file permissions
   chmod 755 user-storage/
   chmod 755 temp-uploads/
   ```

2. **Database Issues**
   ```bash
   # Delete database to recreate (loses all data)
   rm file-organizer.db
   npm start
   ```

3. **Port Already in Use**
   ```bash
   # Check what's using port 3000
   lsof -i :3000
   # Kill the process or change PORT in server.js
   ```

4. **Storage Full**
   - Check user storage quotas in the database
   - Clean up unnecessary files
   - Increase quota if needed

## 📝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the `package.json` file for details.

## 🔄 Version History

- **v1.0.0** - Initial release
  - Multi-user authentication
  - File upload and categorization
  - File preview capabilities
  - Storage quota management
  - Security features

## 📞 Support

For support and questions:
1. Check the troubleshooting section
2. Review the API documentation
3. Create an issue in the repository
4. Check the logs in the console output

## 🎯 Future Enhancements

Potential features for future versions:
- File sharing between users
- Advanced search and filtering
- File versioning
- Bulk operations
- Admin dashboard
- File compression/optimization
- Cloud storage integration
- API rate limiting
- Email notifications

---

**Built with ❤️ for secure file management**
