// package.json
{
  "name": "bookshelf-backend",
  "version": "1.0.0",
  "description": "BookShelf platform backend for NFT book publishing",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^8.0.3",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "cors": "^2.8.5",
    "helmet": "^7.1.0",
    "morgan": "^1.10.0",
    "express-rate-limit": "^7.1.5",
    "joi": "^17.11.0",
    "multer": "^1.4.5-lts.1",
    "razorpay": "^2.9.2",
    "web3": "^4.2.2",
    "axios": "^1.6.2",
    "dotenv": "^16.3.1",
    "express-validator": "^7.0.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.2",
    "jest": "^29.7.0",
    "supertest": "^6.3.3"
  }
}

// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = require('./app');

const PORT = process.env.PORT || 5000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/bookshelf';

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});

// Global middleware
app.use(helmet());
app.use(cors());
app.use(morgan('combined'));
app.use(limiter);

// Connect to MongoDB
mongoose.connect(MONGODB_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    app.listen(PORT, () => {
      console.log(`BookShelf server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  });

// app.js
const express = require('express');
const app = express();

// Import routes
const authRoutes = require('./routes/auth');
const bookRoutes = require('./routes/books');
const ratingRoutes = require('./routes/ratings');
const marketplaceRoutes = require('./routes/marketplace');
const subscriptionRoutes = require('./routes/subscriptions');

// Import middleware
const errorHandler = require('./middlewares/errorHandler');

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/books', bookRoutes);
app.use('/api/ratings', ratingRoutes);
app.use('/api/marketplace', marketplaceRoutes);
app.use('/api/subscriptions', subscriptionRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ success: true, message: 'BookShelf API is running' });
});

// Error handling middleware
app.use(errorHandler);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ success: false, error: 'Route not found' });
});

module.exports = app;

// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    maxlength: 100
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  wallet_address: {
    type: String,
    sparse: true,
    unique: true
  },
  role: {
    type: String,
    enum: ['writer', 'reader', 'admin'],
    default: 'reader'
  },
  created_at: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);

// models/Book.js
const mongoose = require('mongoose');

const bookSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true,
    maxlength: 200
  },
  description: {
    type: String,
    required: true,
    maxlength: 2000
  },
  genre: {
    type: String,
    required: true,
    enum: ['fiction', 'non-fiction', 'mystery', 'romance', 'sci-fi', 'fantasy', 'biography', 'history', 'other']
  },
  cover_image: {
    type: String,
    required: true
  },
  content_ipfs_cid: {
    type: String,
    required: true
  },
  author_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  minted: {
    type: Boolean,
    default: false
  },
  nft_token_id: {
    type: String,
    sparse: true
  },
  royalty_percentage: {
    type: Number,
    default: 10,
    min: 0,
    max: 25
  },
  price_inr: {
    type: Number,
    default: 0,
    min: 0
  },
  rating_avg: {
    type: Number,
    default: 0,
    min: 0,
    max: 5
  },
  rating_count: {
    type: Number,
    default: 0
  },
  created_at: {
    type: Date,
    default: Date.now
  }
});

// Index for searching
bookSchema.index({ title: 'text', description: 'text' });
bookSchema.index({ genre: 1 });
bookSchema.index({ rating_avg: -1 });

module.exports = mongoose.model('Book', bookSchema);

// models/Rating.js
const mongoose = require('mongoose');

const ratingSchema = new mongoose.Schema({
  book_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Book',
    required: true
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  rating: {
    type: Number,
    required: true,
    min: 1,
    max: 5
  },
  review: {
    type: String,
    maxlength: 1000
  },
  created_at: {
    type: Date,
    default: Date.now
  }
});

// Ensure one rating per user per book
ratingSchema.index({ book_id: 1, user_id: 1 }, { unique: true });

module.exports = mongoose.model('Rating', ratingSchema);

// models/Sale.js
const mongoose = require('mongoose');

const saleSchema = new mongoose.Schema({
  book_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Book',
    required: true
  },
  seller_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  buyer_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  price_paid_inr: {
    type: Number,
    required: true,
    min: 0
  },
  tx_hash: {
    type: String,
    required: true
  },
  royalty_paid: {
    type: Boolean,
    default: false
  },
  royalty_amount: {
    type: Number,
    default: 0
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('Sale', saleSchema);

// models/Subscription.js
const mongoose = require('mongoose');

const subscriptionSchema = new mongoose.Schema({
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  start_date: {
    type: Date,
    required: true
  },
  end_date: {
    type: Date,
    required: true
  },
  active: {
    type: Boolean,
    default: true
  },
  payment_reference: {
    type: String,
    required: true
  },
  amount_paid: {
    type: Number,
    required: true
  },
  created_at: {
    type: Date,
    default: Date.now
  }
});

// Index for quick lookup
subscriptionSchema.index({ user_id: 1, active: 1 });

module.exports = mongoose.model('Subscription', subscriptionSchema);

// middlewares/auth.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const authMiddleware = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ success: false, error: 'Access denied. No token provided.' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ success: false, error: 'Token is not valid.' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ success: false, error: 'Token is not valid.' });
  }
};

const roleMiddleware = (roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ success: false, error: 'Access denied. Insufficient permissions.' });
    }
    next();
  };
};

module.exports = { authMiddleware, roleMiddleware };

// middlewares/errorHandler.js
const errorHandler = (err, req, res, next) => {
  console.error(err.stack);

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map(e => e.message);
    return res.status(400).json({ success: false, error: errors.join(', ') });
  }

  // Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return res.status(400).json({ success: false, error: `${field} already exists` });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ success: false, error: 'Invalid token' });
  }

  // Default error
  res.status(500).json({ success: false, error: 'Internal server error' });
};

module.exports = errorHandler;

// middlewares/validation.js
const { body, validationResult } = require('express-validator');

const validateRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
};

const registerValidation = [
  body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Name must be between 2 and 100 characters'),
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  body('role').optional().isIn(['writer', 'reader']).withMessage('Role must be either writer or reader')
];

const loginValidation = [
  body('email').isEmail().normalizeEmail().withMessage('Please provide a valid email'),
  body('password').exists().withMessage('Password is required')
];

const bookValidation = [
  body('title').trim().isLength({ min: 1, max: 200 }).withMessage('Title must be between 1 and 200 characters'),
  body('description').trim().isLength({ min: 10, max: 2000 }).withMessage('Description must be between 10 and 2000 characters'),
  body('genre').isIn(['fiction', 'non-fiction', 'mystery', 'romance', 'sci-fi', 'fantasy', 'biography', 'history', 'other']).withMessage('Invalid genre'),
  body('cover_image').isURL().withMessage('Cover image must be a valid URL'),
  body('content_ipfs_cid').trim().isLength({ min: 1 }).withMessage('Content IPFS CID is required')
];

const ratingValidation = [
  body('rating').isInt({ min: 1, max: 5 }).withMessage('Rating must be between 1 and 5'),
  body('review').optional().trim().isLength({ max: 1000 }).withMessage('Review must be less than 1000 characters')
];

module.exports = {
  validateRequest,
  registerValidation,
  loginValidation,
  bookValidation,
  ratingValidation
};

// controllers/authController.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');

const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '7d' });
};

const register = async (req, res) => {
  try {
    const { name, email, password, role, wallet_address } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, error: 'User already exists with this email' });
    }

    const user = new User({
      name,
      email,
      password,
      role: role || 'reader',
      wallet_address
    });

    await user.save();

    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      data: {
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          wallet_address: user.wallet_address
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const token = generateToken(user._id);

    res.json({
      success: true,
      data: {
        token,
        user: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          wallet_address: user.wallet_address
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const getMe = async (req, res) => {
  try {
    res.json({
      success: true,
      data: {
        user: {
          id: req.user._id,
          name: req.user.name,
          email: req.user.email,
          role: req.user.role,
          wallet_address: req.user.wallet_address
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

module.exports = { register, login, getMe };

// controllers/bookController.js
const Book = require('../models/Book');
const Rating = require('../models/Rating');
const Sale = require('../models/Sale');
const { uploadToIPFS, mintNFT } = require('../services/blockchainService');
const { processPayment } = require('../services/paymentService');

const createBook = async (req, res) => {
  try {
    const { title, description, genre, cover_image, content_ipfs_cid, royalty_percentage } = req.body;

    const book = new Book({
      title,
      description,
      genre,
      cover_image,
      content_ipfs_cid,
      author_id: req.user._id,
      royalty_percentage: royalty_percentage || 10
    });

    await book.save();
    await book.populate('author_id', 'name email');

    res.status(201).json({
      success: true,
      data: { book }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const mintBookNFT = async (req, res) => {
  try {
    const bookId = req.params.id;
    const { payment_id } = req.body;

    const book = await Book.findById(bookId);
    if (!book) {
      return res.status(404).json({ success: false, error: 'Book not found' });
    }

    if (book.author_id.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, error: 'Only the author can mint this book' });
    }

    if (book.minted) {
      return res.status(400).json({ success: false, error: 'Book already minted' });
    }

    // Verify payment of ₹130
    const paymentValid = await processPayment(payment_id, 13000); // 130 INR in paise
    if (!paymentValid) {
      return res.status(400).json({ success: false, error: 'Payment verification failed' });
    }

    // Mint NFT
    const nftTokenId = await mintNFT(book, req.user.wallet_address);

    book.minted = true;
    book.nft_token_id = nftTokenId;
    await book.save();

    res.json({
      success: true,
      data: {
        message: 'Book successfully minted as NFT',
        nft_token_id: nftTokenId
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const getBooks = async (req, res) => {
  try {
    const { genre, page = 1, limit = 10, sort = 'created_at' } = req.query;
    const skip = (page - 1) * limit;

    let filter = {};
    if (genre) filter.genre = genre;

    let sortOptions = {};
    switch (sort) {
      case 'rating':
        sortOptions = { rating_avg: -1 };
        break;
      case 'price_low':
        sortOptions = { price_inr: 1 };
        break;
      case 'price_high':
        sortOptions = { price_inr: -1 };
        break;
      default:
        sortOptions = { created_at: -1 };
    }

    const books = await Book.find(filter)
      .populate('author_id', 'name')
      .sort(sortOptions)
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Book.countDocuments(filter);

    res.json({
      success: true,
      data: {
        books,
        pagination: {
          current_page: parseInt(page),
          total_pages: Math.ceil(total / limit),
          total_books: total
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const getBook = async (req, res) => {
  try {
    const book = await Book.findById(req.params.id).populate('author_id', 'name email');
    
    if (!book) {
      return res.status(404).json({ success: false, error: 'Book not found' });
    }

    res.json({
      success: true,
      data: { book }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const updateBook = async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);
    
    if (!book) {
      return res.status(404).json({ success: false, error: 'Book not found' });
    }

    if (book.author_id.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, error: 'Only the author can update this book' });
    }

    const allowedUpdates = ['title', 'description', 'cover_image', 'price_inr'];
    const updates = {};
    
    allowedUpdates.forEach(field => {
      if (req.body[field] !== undefined) {
        updates[field] = req.body[field];
      }
    });

    const updatedBook = await Book.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true, runValidators: true }
    ).populate('author_id', 'name email');

    res.json({
      success: true,
      data: { book: updatedBook }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const deleteBook = async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);
    
    if (!book) {
      return res.status(404).json({ success: false, error: 'Book not found' });
    }

    if (book.author_id.toString() !== req.user._id.toString() && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Not authorized to delete this book' });
    }

    await Book.findByIdAndDelete(req.params.id);
    await Rating.deleteMany({ book_id: req.params.id });

    res.json({
      success: true,
      data: { message: 'Book deleted successfully' }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

module.exports = {
  createBook,
  mintBookNFT,
  getBooks,
  getBook,
  updateBook,
  deleteBook
};

// controllers/ratingController.js
const Rating = require('../models/Rating');
const Book = require('../models/Book');

const rateBook = async (req, res) => {
  try {
    const { rating, review } = req.body;
    const bookId = req.params.id;

    const book = await Book.findById(bookId);
    if (!book) {
      return res.status(404).json({ success: false, error: 'Book not found' });
    }

    // Check if user already rated this book
    const existingRating = await Rating.findOne({
      book_id: bookId,
      user_id: req.user._id
    });

    if (existingRating) {
      // Update existing rating
      existingRating.rating = rating;
      existingRating.review = review || existingRating.review;
      await existingRating.save();
    } else {
      // Create new rating
      const newRating = new Rating({
        book_id: bookId,
        user_id: req.user._id,
        rating,
        review
      });
      await newRating.save();
    }

    // Recalculate book's average rating
    const ratings = await Rating.find({ book_id: bookId });
    const avgRating = ratings.reduce((sum, r) => sum + r.rating, 0) / ratings.length;

    await Book.findByIdAndUpdate(bookId, {
      rating_avg: Math.round(avgRating * 10) / 10, // Round to 1 decimal
      rating_count: ratings.length
    });

    res.json({
      success: true,
      data: {
        message: existingRating ? 'Rating updated successfully' : 'Rating added successfully',
        rating: existingRating || newRating
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const getBookRatings = async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;

    const ratings = await Rating.find({ book_id: req.params.id })
      .populate('user_id', 'name')
      .sort({ created_at: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Rating.countDocuments({ book_id: req.params.id });

    res.json({
      success: true,
      data: {
        ratings,
        pagination: {
          current_page: parseInt(page),
          total_pages: Math.ceil(total / limit),
          total_ratings: total
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

module.exports = { rateBook, getBookRatings };

// routes/auth.js
const express = require('express');
const router = express.Router();
const { register, login, getMe } = require('../controllers/authController');
const { authMiddleware } = require('../middlewares/auth');
const { registerValidation, loginValidation, validateRequest } = require('../middlewares/validation');

router.post('/register', registerValidation, validateRequest, register);
router.post('/login', loginValidation, validateRequest, login);
router.get('/me', authMiddleware, getMe);

module.exports = router;

// routes/books.js
const express = require('express');
const router = express.Router();
const {
  createBook,
  mintBookNFT,
  getBooks,
  getBook,
  updateBook,
  deleteBook
} = require('../controllers/bookController');
const { authMiddleware, roleMiddleware } = require('../middlewares/auth');
const { bookValidation, validateRequest } = require('../middlewares/validation');

router.post('/', authMiddleware, roleMiddleware(['writer']), bookValidation, validateRequest, createBook);
router.post('/:id/mint', authMiddleware, roleMiddleware(['writer']), mintBookNFT);
router.get('/', getBooks);
router.get('/:id', getBook);
router.patch('/:id', authMiddleware, roleMiddleware(['writer']), updateBook);
router.delete('/:id', authMiddleware, deleteBook);

module.exports = router;

// routes/ratings.js
const express = require('express');
const router = express.Router();
const { rateBook, getBookRatings } = require('../controllers/ratingController');
const { authMiddleware } = require('../middlewares/auth');
const { ratingValidation, validateRequest } = require('../middlewares/validation');

router.post('/books/:id/rate', authMiddleware, ratingValidation, validateRequest, rateBook);
router.get('/books/:id/ratings', getBookRatings);

module.exports = router;

// services/blockchainService.js
const Web3 = require('web3');

// Mock implementation - replace with actual smart contract integration
const web3 = new Web3(process.env.BLOCKCHAIN_RPC_URL || 'http://localhost:8545');

const uploadToIPFS = async (content) => {
  // Mock implementation - integrate with actual IPFS service
  // You can use web3.storage, Pinata, or your own IPFS node
  try {
    // Simulate IPFS upload
    const mockCID = 'Qm' + Math.random().toString(36).substring(2, 15);
    return mockCID;
  } catch (error) {
    throw new Error('IPFS upload failed: ' + error.message);
  }
};

const mintNFT = async (book, walletAddress) => {
  // Mock implementation - replace with actual NFT minting
  try {
    // This would interact with your NFT smart contract
    const mockTokenId = Date.now().toString();
    
    // Simulate blockchain transaction
    console.log(`Minting NFT for book: ${book.title}`);
    console.log(`Wallet: ${walletAddress}`);
    
    return mockTokenId;
  } catch (error) {
    throw new Error('NFT minting failed: ' + error.message);
  }
};

const transferNFT = async (tokenId, fromAddress, toAddress) => {
  // Mock implementation for NFT transfer
  try {
    console.log(`Transferring NFT ${tokenId} from ${fromAddress} to ${toAddress}`);
    const mockTxHash = '0x' + Math.random().toString(16).substring(2, 66);
    return mockTxHash;
  } catch (error) {
    throw new Error('NFT transfer failed: ' + error.message);
  }
};

module.exports = { uploadToIPFS, mintNFT, transferNFT };

// services/paymentService.js
const Razorpay = require('razorpay');

const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

const processPayment = async (paymentId, expectedAmount) => {
  try {
    const payment = await razorpay.payments.fetch(paymentId);
    
    if (payment.status === 'captured' && payment.amount === expectedAmount) {
      return true;
    }
    return false;
  } catch (error) {
    console.error('Payment verification failed:', error);
    return false;
  }
};

const createOrder = async (amount, currency = 'INR') => {
  try {
    const order = await razorpay.orders.create({
      amount: amount, // Amount in paise
      currency,
      payment_capture: 1
    });
    return order;
  } catch (error) {
    throw new Error('Order creation failed: ' + error.message);
  }
};

const calculateRoyalty = (salePrice, royaltyPercentage) => {
  return Math.round((salePrice * royaltyPercentage) / 100);
};

module.exports = { processPayment, createOrder, calculateRoyalty };

// controllers/marketplaceController.js
const Book = require('../models/Book');
const Sale = require('../models/Sale');
const User = require('../models/User');
const { transferNFT } = require('../services/blockchainService');
const { processPayment, calculateRoyalty } = require('../services/paymentService');

const listBookForSale = async (req, res) => {
  try {
    const { price_inr } = req.body;
    const bookId = req.params.id;

    const book = await Book.findById(bookId);
    if (!book) {
      return res.status(404).json({ success: false, error: 'Book not found' });
    }

    if (!book.minted) {
      return res.status(400).json({ success: false, error: 'Book must be minted as NFT before listing' });
    }

    // Check if user owns this NFT (in a real implementation, verify blockchain ownership)
    const lastSale = await Sale.findOne({ book_id: bookId }).sort({ timestamp: -1 });
    const currentOwner = lastSale ? lastSale.buyer_id : book.author_id;

    if (currentOwner.toString() !== req.user._id.toString()) {
      return res.status(403).json({ success: false, error: 'You do not own this NFT' });
    }

    await Book.findByIdAndUpdate(bookId, { price_inr });

    res.json({
      success: true,
      data: {
        message: 'Book listed for sale successfully',
        price_inr
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const buyBook = async (req, res) => {
  try {
    const { payment_id } = req.body;
    const bookId = req.params.id;

    const book = await Book.findById(bookId).populate('author_id');
    if (!book) {
      return res.status(404).json({ success: false, error: 'Book not found' });
    }

    if (!book.minted || book.price_inr <= 0) {
      return res.status(400).json({ success: false, error: 'Book not available for sale' });
    }

    // Find current owner
    const lastSale = await Sale.findOne({ book_id: bookId }).sort({ timestamp: -1 });
    const currentOwner = lastSale ? lastSale.buyer_id : book.author_id._id;

    if (currentOwner.toString() === req.user._id.toString()) {
      return res.status(400).json({ success: false, error: 'You already own this book' });
    }

    // Verify payment
    const paymentAmount = book.price_inr * 100; // Convert to paise
    const paymentValid = await processPayment(payment_id, paymentAmount);
    if (!paymentValid) {
      return res.status(400).json({ success: false, error: 'Payment verification failed' });
    }

    // Calculate royalty
    const royaltyAmount = calculateRoyalty(book.price_inr, book.royalty_percentage);

    // Transfer NFT on blockchain
    const seller = await User.findById(currentOwner);
    const txHash = await transferNFT(book.nft_token_id, seller.wallet_address, req.user.wallet_address);

    // Record sale
    const sale = new Sale({
      book_id: bookId,
      seller_id: currentOwner,
      buyer_id: req.user._id,
      price_paid_inr: book.price_inr,
      tx_hash: txHash,
      royalty_paid: true,
      royalty_amount
    });

    await sale.save();

    // Remove from sale (set price to 0)
    await Book.findByIdAndUpdate(bookId, { price_inr: 0 });

    res.json({
      success: true,
      data: {
        message: 'Book purchased successfully',
        sale_id: sale._id,
        tx_hash: txHash,
        royalty_paid: royaltyAmount
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const getMarketplace = async (req, res) => {
  try {
    const { genre, page = 1, limit = 10, sort = 'created_at' } = req.query;
    const skip = (page - 1) * limit;

    let filter = { minted: true, price_inr: { $gt: 0 } };
    if (genre) filter.genre = genre;

    let sortOptions = {};
    switch (sort) {
      case 'price_low':
        sortOptions = { price_inr: 1 };
        break;
      case 'price_high':
        sortOptions = { price_inr: -1 };
        break;
      case 'rating':
        sortOptions = { rating_avg: -1 };
        break;
      default:
        sortOptions = { created_at: -1 };
    }

    const books = await Book.find(filter)
      .populate('author_id', 'name')
      .sort(sortOptions)
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Book.countDocuments(filter);

    res.json({
      success: true,
      data: {
        books,
        pagination: {
          current_page: parseInt(page),
          total_pages: Math.ceil(total / limit),
          total_books: total
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const getSalesHistory = async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;
    const skip = (page - 1) * limit;

    const sales = await Sale.find({ buyer_id: req.user._id })
      .populate('book_id', 'title cover_image')
      .populate('seller_id', 'name')
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Sale.countDocuments({ buyer_id: req.user._id });

    res.json({
      success: true,
      data: {
        sales,
        pagination: {
          current_page: parseInt(page),
          total_pages: Math.ceil(total / limit),
          total_sales: total
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

module.exports = {
  listBookForSale,
  buyBook,
  getMarketplace,
  getSalesHistory
};

// controllers/subscriptionController.js
const Subscription = require('../models/Subscription');
const { processPayment, createOrder } = require('../services/paymentService');

const startSubscription = async (req, res) => {
  try {
    const { payment_id, duration_months = 1 } = req.body;
    const subscriptionPrice = 299; // ₹299 per month

    const totalAmount = subscriptionPrice * duration_months;
    const paymentAmount = totalAmount * 100; // Convert to paise

    // Verify payment
    const paymentValid = await processPayment(payment_id, paymentAmount);
    if (!paymentValid) {
      return res.status(400).json({ success: false, error: 'Payment verification failed' });
    }

    // Check if user already has an active subscription
    const existingSubscription = await Subscription.findOne({
      user_id: req.user._id,
      active: true,
      end_date: { $gt: new Date() }
    });

    const startDate = existingSubscription ? existingSubscription.end_date : new Date();
    const endDate = new Date(startDate);
    endDate.setMonth(endDate.getMonth() + duration_months);

    // Deactivate existing subscription if any
    if (existingSubscription) {
      existingSubscription.active = false;
      await existingSubscription.save();
    }

    const subscription = new Subscription({
      user_id: req.user._id,
      start_date: startDate,
      end_date: endDate,
      active: true,
      payment_reference: payment_id,
      amount_paid: totalAmount
    });

    await subscription.save();

    res.json({
      success: true,
      data: {
        message: 'Subscription activated successfully',
        subscription: {
          id: subscription._id,
          start_date: subscription.start_date,
          end_date: subscription.end_date,
          amount_paid: subscription.amount_paid
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const validateSubscription = async (req, res) => {
  try {
    const subscription = await Subscription.findOne({
      user_id: req.user._id,
      active: true,
      end_date: { $gt: new Date() }
    });

    if (!subscription) {
      return res.json({
        success: true,
        data: {
          hasActiveSubscription: false,
          message: 'No active subscription found'
        }
      });
    }

    res.json({
      success: true,
      data: {
        hasActiveSubscription: true,
        subscription: {
          id: subscription._id,
          start_date: subscription.start_date,
          end_date: subscription.end_date,
          days_remaining: Math.ceil((subscription.end_date - new Date()) / (1000 * 60 * 60 * 24))
        }
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

const createSubscriptionOrder = async (req, res) => {
  try {
    const { duration_months = 1 } = req.body;
    const subscriptionPrice = 299; // ₹299 per month
    const totalAmount = subscriptionPrice * duration_months * 100; // Convert to paise

    const order = await createOrder(totalAmount);

    res.json({
      success: true,
      data: {
        order,
        amount_inr: totalAmount / 100,
        duration_months
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
};

module.exports = {
  startSubscription,
  validateSubscription,
  createSubscriptionOrder
};

// routes/marketplace.js
const express = require('express');
const router = express.Router();
const {
  listBookForSale,
  buyBook,
  getMarketplace,
  getSalesHistory
} = require('../controllers/marketplaceController');
const { authMiddleware } = require('../middlewares/auth');
const { body, validateRequest } = require('../middlewares/validation');

const listBookValidation = [
  body('price_inr').isFloat({ min: 1 }).withMessage('Price must be a positive number')
];

const buyBookValidation = [
  body('payment_id').trim().isLength({ min: 1 }).withMessage('Payment ID is required')
];

router.post('/books/:id/list', authMiddleware, listBookValidation, validateRequest, listBookForSale);
router.post('/books/:id/buy', authMiddleware, buyBookValidation, validateRequest, buyBook);
router.get('/', getMarketplace);
router.get('/my-purchases', authMiddleware, getSalesHistory);

module.exports = router;

// routes/subscriptions.js
const express = require('express');
const router = express.Router();
const {
  startSubscription,
  validateSubscription,
  createSubscriptionOrder
} = require('../controllers/subscriptionController');
const { authMiddleware } = require('../middlewares/auth');
const { body, validateRequest } = require('../middlewares/validation');

const subscriptionValidation = [
  body('payment_id').trim().isLength({ min: 1 }).withMessage('Payment ID is required'),
  body('duration_months').optional().isInt({ min: 1, max: 12 }).withMessage('Duration must be between 1 and 12 months')
];

const orderValidation = [
  body('duration_months').optional().isInt({ min: 1, max: 12 }).withMessage('Duration must be between 1 and 12 months')
];

router.post('/start', authMiddleware, subscriptionValidation, validateRequest, startSubscription);
router.get('/validate', authMiddleware, validateSubscription);
router.post('/create-order', authMiddleware, orderValidation, validateRequest, createSubscriptionOrder);

module.exports = router;

// utils/helpers.js
const crypto = require('crypto');

const generateRandomString = (length = 32) => {
  return crypto.randomBytes(length).toString('hex');
};

const calculateDynamicPricing = (basePrice, rating, ratingCount) => {
  if (ratingCount < 5) return basePrice;
  
  const ratingMultiplier = rating / 5; // 0.2 to 1.0
  const popularityBonus = Math.min(ratingCount / 100, 0.5); // Up to 50% bonus
  
  return Math.round(basePrice * (0.7 + ratingMultiplier * 0.3 + popularityBonus));
};

const validateIPFSHash = (hash) => {
  // Basic IPFS hash validation
  return /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/.test(hash);
};

const sanitizeText = (text) => {
  return text.replace(/<[^>]*>?/gm, ''); // Remove HTML tags
};

module.exports = {
  generateRandomString,
  calculateDynamicPricing,
  validateIPFSHash,
  sanitizeText
};

// .env.example
NODE_ENV=development
PORT=5000
MONGODB_URI=mongodb://localhost:27017/bookshelf
JWT_SECRET=your_super_secret_jwt_key_here

# Razorpay Configuration
RAZORPAY_KEY_ID=your_razorpay_key_id
RAZORPAY_KEY_SECRET=your_razorpay_key_secret

# Blockchain Configuration
BLOCKCHAIN_RPC_URL=http://localhost:8545
NFT_CONTRACT_ADDRESS=0x...
PRIVATE_KEY=your_wallet_private_key

# IPFS Configuration
IPFS_API_URL=https://api.pinata.cloud
PINATA_API_KEY=your_pinata_api_key
PINATA_SECRET_KEY=your_pinata_secret_key

# Email Configuration (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password

// README.md
# BookShelf Backend API

A comprehensive Node.js backend for the BookShelf platform - an NFT-based book publishing and marketplace system.

## Features

- **User Management**: Registration, authentication with JWT
- **Book Publishing**: Create books with IPFS content storage
- **NFT Minting**: Mint books as NFTs with ₹130 payment
- **Marketplace**: Buy/sell NFT books with royalty enforcement
- **Subscriptions**: Reader subscriptions for book access
- **Rating System**: Rate and review books
- **Payment Integration**: Razorpay for payments

## Tech Stack

- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB with Mongoose
- **Authentication**: JWT + bcrypt
- **Payments**: Razorpay
- **Blockchain**: Web3.js (mock implementation)
- **Storage**: IPFS integration ready

## Installation

```bash
# Clone repository
git clone <repository-url>
cd bookshelf-backend

# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Edit .env with your configuration
nano .env

# Start development server
npm run dev
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `GET /api/auth/me` - Get current user info

### Books
- `POST /api/books` - Create book (writers only)
- `POST /api/books/:id/mint` - Mint book as NFT
- `GET /api/books` - List all books
- `GET /api/books/:id` - Get single book
- `PATCH /api/books/:id` - Update book (author only)
- `DELETE /api/books/:id` - Delete book

### Ratings
- `POST /api/ratings/books/:id/rate` - Rate a book
- `GET /api/ratings/books/:id/ratings` - Get book ratings

### Marketplace
- `POST /api/marketplace/books/:id/list` - List book for sale
- `POST /api/marketplace/books/:id/buy` - Buy book NFT
- `GET /api/marketplace` - Browse marketplace
- `GET /api/marketplace/my-purchases` - User's purchase history

### Subscriptions
- `POST /api/subscriptions/create-order` - Create subscription order
- `POST /api/subscriptions/start` - Start subscription
- `GET /api/subscriptions/validate` - Check subscription status

## Database Schema

### User Model
```javascript
{
  name: String,
  email: String (unique),
  password: String (hashed),
  wallet_address: String,
  role: Enum['writer', 'reader', 'admin'],
  created_at: Date
}
```

### Book Model
```javascript
{
  title: String,
  description: String,
  genre: Enum,
  cover_image: String (URL),
  content_ipfs_cid: String,
  author_id: ObjectId,
  minted: Boolean,
  nft_token_id: String,
  royalty_percentage: Number,
  price_inr: Number,
  rating_avg: Number,
  created_at: Date
}
```

## Key Features Implementation

### NFT Minting Process
1. User creates book with IPFS content
2. Pays ₹130 minting fee via Razorpay
3. Smart contract mints NFT
4. Book marked as minted with token ID

### Royalty System
- Configurable royalty percentage per book
- Automatic royalty calculation on resales
- Payments to original authors on secondary sales

### Subscription Access
- Monthly subscription for readers
- Access to all minted books during active subscription
- Automatic subscription validation

### Dynamic Pricing
- Rating-based pricing suggestions
- Popularity bonuses for highly-rated books
- Market-driven price discovery

## Security Features

- JWT authentication with 7-day expiry
- Password hashing with bcrypt
- Rate limiting on API endpoints
- Input validation and sanitization
- Role-based access control
- Helmet.js security headers

## Development

```bash
# Run in development mode
npm run dev

# Run tests
npm test

# Production start
npm start
```

## Environment Variables

See `.env.example` for all required environment variables.

## Integration Notes

### Blockchain Integration
- Currently uses mock implementations
- Replace with actual smart contract calls
- Ensure proper wallet connection and transaction handling

### IPFS Integration
- Ready for Pinata or web3.storage integration
- Implement actual file upload to IPFS
- Store CID references in database

### Payment Integration
- Razorpay integration implemented
- Webhook handling for payment confirmations
- Support for INR payments

## License

MIT License
