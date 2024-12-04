const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const db = require('./db');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(bodyParser.json());

// Транспортер для отправки email
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL,
        pass: process.env.EMAIL_PASSWORD,
    },
});

// Генерация токена подтверждения email
const generateToken = (email) => jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

// Проверка токена
const verifyToken = (token) => jwt.verify(token, process.env.JWT_SECRET);

// Получение всех пользователей
app.get('/users', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM users');
        res.status(200).json(results);
    } catch (err) {
        res.status(500).send(err);
    }
});

// Авторизация пользователя
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).send('Email and password are required');

    try {
        const [results] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (results.length === 0) return res.status(404).send('User not found');

        const user = results[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) return res.status(401).send('Invalid credentials');

        const token = jwt.sign({ id: user.id, kidsMode: user.kids_mode }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login successful', token });
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// Регистрация нового пользователя
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) return res.status(400).send('Email and password are required');

    try {
        const [results] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (results.length > 0) return res.status(409).send('User already exists');

        const hashedPassword = await bcrypt.hash(password, 10);
        const token = generateToken(email);

        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Подтверждение регистрации',
            text: `Перейдите по ссылке, чтобы завершить регистрацию: http://localhost:${PORT}/verify?token=${token}`,
        };

        await transporter.sendMail(mailOptions);
        await db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hashedPassword]);

        res.status(200).send('Verification email sent');
    } catch (err) {
        res.status(500).send('Error during registration');
    }
});

// Подтверждение email
app.get('/verify', async (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(400).send('Token is required');

    try {
        const { email } = verifyToken(token);
        const [results] = await db.query('SELECT * FROM users WHERE email = ?', [email]);

        if (results.length === 0) return res.status(404).send('User not found');

        res.status(200).send('Email verified successfully. You can now log in.');
    } catch (err) {
        res.status(400).send('Invalid or expired token');
    }
});

// Получение профилей пользователя
app.get('/profiles/:userId', async (req, res) => {
    const { userId } = req.params;

    try {
        const [results] = await db.query('SELECT * FROM profiles WHERE user_id = ?', [userId]);
        res.status(200).json(results);
    } catch (err) {
        res.status(500).send(err);
    }
});

// Создание нового профиля
app.post('/profiles', async (req, res) => {
    const { userId, name, avatarUrl } = req.body;

    if (!userId || !name) return res.status(400).send('User ID and profile name are required');

    try {
        await db.query('INSERT INTO profiles (user_id, name, avatar_url) VALUES (?, ?, ?)', [userId, name, avatarUrl || null]);
        res.status(201).send('Profile created successfully');
    } catch (err) {
        res.status(500).send(err);
    }
});

// Удаление профиля
app.delete('/profiles/:id', async (req, res) => {
    const { id } = req.params;

    try {
        await db.query('DELETE FROM profiles WHERE id = ?', [id]);
        res.status(200).send('Profile deleted successfully');
    } catch (err) {
        res.status(500).send(err);
    }
});

// Получить все фильмы
app.get('/movies', async (req, res) => {
    try {
        const [results] = await db.query('SELECT * FROM movies');
        res.status(200).json(results);
    } catch (err) {
        res.status(500).send(err);
    }
});

// Фильтровать фильмы по жанру
app.get('/movies/genre/:genre', async (req, res) => {
    const { genre } = req.params;

    try {
        const [results] = await db.query('SELECT * FROM movies WHERE genre = ?', [genre]);
        res.status(200).json(results);
    } catch (err) {
        res.status(500).send(err);
    }
});

// Увеличение количества просмотров
app.post('/movies/view/:id', async (req, res) => {
    const { id } = req.params;

    try {
        await db.query('UPDATE movies SET views = views + 1 WHERE id = ?', [id]);
        res.status(200).send('View count updated');
    } catch (err) {
        res.status(500).send('Error updating views');
    }
});

// Добавление нового фильма
app.post('/movies', async (req, res) => {
    const { title, video_url } = req.body;

    if (!title || !video_url) return res.status(400).send('Title and video URL are required');

    try {
        await db.query('INSERT INTO movies (title, video_url) VALUES (?, ?)', [title, video_url]);
        res.status(201).send('Movie added successfully');
    } catch (err) {
        res.status(500).send('Error adding movie');
    }
});

// Запрос на сброс пароля
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).send('Email is required');

    try {
        const [results] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (results.length === 0) return res.status(404).send('User not found');

        const resetToken = generateToken(email);
        const resetLink = `http://localhost:${PORT}/reset-password?token=${resetToken}`;

        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Password Reset Request',
            text: `Click the following link to reset your password: ${resetLink}`,
        };

        await transporter.sendMail(mailOptions);
        res.status(200).send('Password reset email sent');
    } catch (err) {
        res.status(500).send('Server error');
    }
});

// Сброс пароля
app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).send('Token and new password are required');

    try {
        const { email } = verifyToken(token);
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);
        res.status(200).send('Password has been reset successfully');
    } catch (err) {
        res.status(400).send('Invalid or expired token');
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
