const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const Paste = require('./paste');
const session = require('express-session');
const User = require('./models/user');
const bcrypt = require('bcrypt');
const MongoStore = require('connect-mongo');
const { isAuthenticated } = require('./middleware');
const crypto = require('crypto');
const favicon = require('serve-favicon');
const path = require('path');




// ... (previoconst express = require('express');



// Store user ID in the session


// Connect to MongoDB
mongoose.connect('mongodb+srv://cloxbot:XbtZayZVJMP6oqMm@cluster0.wpxew.mongodb.net/?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const db = mongoose.connection;

db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});



const app = express();

app.use('/public', express.static('public'));

app.use(favicon(path.join(__dirname, 'public', 'favicon.ico')));

app.use(session({
  secret: 'amna', 
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({ 
    mongoUrl: 'mongodb+srv://cloxbot:XbtZayZVJMP6oqMm@cluster0.wpxew.mongodb.net/?retryWrites=true&w=majority'
  })
}));


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.get('/', async (req, res) => {
    const userId = req.session.userId;

    let isAdmin = false;
    let user = null; // Initialize user as null

    if (userId) {
        try {
            user = await User.findById(userId);
            if (user && user.isAdmin) {
                isAdmin = true;
            }
        } catch (error) {
            console.error("Error fetching user data:", error);
        }
    }

    const isAuthenticated = !!userId; // Use userId directly here
    res.render('index', { isAuthenticated, isAdmin, user });  // Pass the user object here
});



const rateLimit = require('express-rate-limit');

// Define a rate limiter for paste creation
const createPasteLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute in milliseconds
  max: 3, // limit each IP to 1 request per windowMs
  message: "Too many pastes created from this IP, please try again after a minute"
});





// Apply the rate limiter to the route responsible for creating pastes



app.post('/create', createPasteLimiter, async (req, res) => {
    const name = req.body.pasteName || "Untitled Paste"; // If no title is provided, default to "Untitled"
    const content = req.body.content;
    const language = req.body.language || "plaintext"; // Set a default language if none is provided

    let expirationDate;
    switch (req.body.expiration) {
        case '10m':
            expirationDate = new Date(Date.now() + 10 * 60 * 1000);
            break;
        case '1h':
            expirationDate = new Date(Date.now() + 60 * 60 * 1000);
            break;
        case '1d':
            expirationDate = new Date(Date.now() + 24 * 60 * 60 * 1000);
            break;
        default:
            expirationDate = null;
            break;
    }

    const pasteData = {
        name,
        content,
        language,
        expiration: expirationDate,
        password: req.body.password ? req.body.password : null
    };

    if (req.session.userId) {
        pasteData.userId = req.session.userId;
    }

    const paste = new Paste(pasteData);

    try {
        await paste.save();
        res.redirect(`/view/${paste._id}`);
    } catch (error) {
        console.error(error);
        res.status(500).send('Error saving paste');
    }
});

function formatTimeAgo(date) {
  const now = new Date();
  const diffInSeconds = Math.floor((now - date) / 1000);

  const minute = 60;
  const hour = minute * 60;
  const day = hour * 24;
  const week = day * 7;
  const month = day * 30; // approx.
  const year = day * 365; // approx.

  if (diffInSeconds < minute) return `${diffInSeconds} seconds ago`;
  if (diffInSeconds < hour) return `${Math.floor(diffInSeconds / minute)} minutes ago`;
  if (diffInSeconds < day) return `${Math.floor(diffInSeconds / hour)} hours ago`;
  if (diffInSeconds < week) return `${Math.floor(diffInSeconds / day)} days ago`;
  if (diffInSeconds < month) return `${Math.floor(diffInSeconds / week)} weeks ago`;
  if (diffInSeconds < year) return `${Math.floor(diffInSeconds / month)} months ago`;
  
  return `${Math.floor(diffInSeconds / year)} years ago`;
}


function formatTimeUntilExpire(date) {
  const now = new Date();
  const diffInSeconds = Math.floor((date - now) / 1000);

  if (diffInSeconds < 0) return "Never expire";

  const minute = 60;
  const hour = minute * 60;
  const day = hour * 24;
  const week = day * 7;
  const month = day * 30; // approx.
  const year = day * 365; // approx.

  if (diffInSeconds < minute) return `Expires in ${diffInSeconds} seconds`;
  if (diffInSeconds < hour) return `Expires in ${Math.floor(diffInSeconds / minute)} minutes`;
  if (diffInSeconds < day) return `Expires in ${Math.floor(diffInSeconds / hour)} hours`;
  if (diffInSeconds < week) return `Expires in ${Math.floor(diffInSeconds / day)} days`;
  if (diffInSeconds < month) return `Expires in ${Math.floor(diffInSeconds / week)} weeks`;
  if (diffInSeconds < year) return `Expires in ${Math.floor(diffInSeconds / month)} months`;
  
  return `Expires in ${Math.floor(diffInSeconds / year)} years`;
}



app.get('/view/:paste_id', async (req, res) => {
    try {
         const paste = await Paste.findById(req.params.paste_id).populate('userId');
         const user = paste.userId;
        if (paste) {
            // Check for expiration
            if (paste.expiration && paste.expiration < new Date()) {
                await Paste.findByIdAndDelete(req.params.paste_id);
                return res.status(410).send('This paste has expired and has been deleted.');
            }

            // Check for password protection
           
                  if (paste.password) {
                    if (req.query.password !== paste.password) {
                        let isAdmin = false;
                        const userIdFromSession = req.session.userId;
                        if (userIdFromSession) {
                            const userFromSession = await User.findById(userIdFromSession);
                            if (userFromSession && userFromSession.isAdmin) {
                                isAdmin = true;
                            }
                        }
  

                    // If password is not provided or incorrect, render a password input form
                    return res.render('passwordInput', { 
                      pasteId: req.params.paste_id,
                      isAuthenticated: !!userIdFromSession,
                      isAdmin: isAdmin,
                      user
                  });
                  
                }
            }

            // Determine the identifier (user ID or session ID)
            const identifier = req.session.userId || req.sessionID;

            // Hash the identifier
            const hash = crypto.createHash('sha256').update(identifier).digest('hex');

            // Check if this hashed identifier has viewed the paste before
            if (!paste.viewedBySessions.includes(hash)) {
                // Increment view count and store the hash
                paste.views += 1;
                paste.viewedBySessions.push(hash);
                await paste.save();
            }

            const user = paste.userId; // This will now be the full user object since we populated it

            // Determine if user is authenticated
            const isAuthenticated = Boolean(req.session.userId);

            // Render the paste view with both the paste and user details
            res.render('pasteView', { paste, user, isAuthenticated ,formatTimeAgo, formatTimeUntilExpire});
        } else {
            res.status(404).render('404');
        }
    } catch (error) {
        console.error(error);
        res.status(500).render('404');
    }
});


setInterval(async () => {
    const now = new Date();
    await Paste.deleteMany({ expiration: { $lt: now } });
}, 60 * 60 * 1000); // Run every hour



app.post('/view/:paste_id/verify-password', async (req, res) => {
    const paste = await Paste.findById(req.params.paste_id);

    if (req.body.password === paste.password) {
        req.session[`paste_access_${paste._id}`] = true;
        return res.redirect(`/view/${paste._id}`);
    }

    // Handle incorrect password, e.g., show an error message
    return res.render('passwordPrompt', { error: 'Incorrect password' });
});


app.get('/view/:paste_id/content', async (req, res) => {
  try {
    const paste = await Paste.findById(req.params.paste_id);
    if (paste) {
      res.send(paste.content);
    } else {
      res.status(404).render('404');
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Error fetching paste content');
  }
});

app.get('/view/:paste_id/name', async (req, res) => {
  try {
    const paste = await Paste.findById(req.params.paste_id);
    if (paste) {
      res.send(paste.name);
    } else {
      res.status(404).send('Paste not found');
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Error fetching paste name');
  }
});

function checkAuthenticated(req, res, next) {
  if (req.session.userId) {
    // User is authenticated, redirect to dashboard or other authorized page
    return res.redirect('/');
  }
  // User is not authenticated, proceed to next middleware
  next();
}
app.get('/register', checkAuthenticated, async (req, res) => {
  const isAuthenticated = !!req.session.userId;
  let user = null;
  let isAdmin = false;

  if (req.session.userId) {
      user = await User.findById(req.session.userId);  // Use await here
      isAdmin = user && user.isAdmin;
  }

  res.render('register', {  // Change 'profile' to 'register' if you want to render the register.ejs view
      isAdmin: isAdmin,
      user: user,
      isAuthenticated: isAuthenticated 
  });
});




app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  const usernameLowercase = username.toLowerCase();

  // Validate password length
  if (password.length < 8) {
    return res.render('register', { error: 'Password should be at least 8 characters.' });
  }

  // Validate username length
  if (username.length < 3) {
    return res.render('register', { error: 'Username should be at least 3 characters.' });
  }

  try {
    // Check if username or email already exists in the database
    const userWithSameUsername = await User.findOne({ usernameLowercase });
    const userWithSameEmail = await User.findOne({ email });

    if (userWithSameUsername) {
        return res.render('register', { error: 'Username is already taken.' });
    }
    if (userWithSameEmail) {
      return res.render('register', { error: 'Email is already registered.' });
    }

    const user = new User({ username, usernameLowercase, email, password });
        await user.save();
        req.session.userId = user._id;
        res.redirect('/');
    } catch (error) {
        console.error(error);
        res.render('register', { error: 'Error registering user' });
    }
});







// index.js
// ... (previous code)

// Profile route (requires authentication)
app.get('/profile', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    try {
        const user = await User.findById(userId);
        if (user) {
            const pastesCount = await Paste.countDocuments({ userId: userId });  // Count user's pastes
            let viewsCount = 0;
            const userPastes = await Paste.find({ userId: userId });
            for (let paste of userPastes) {
                if (typeof paste.views === "number") {
                    viewsCount += paste.views;
                }
            }
            // Render the profile view with the user's pastes as well
            res.render('profile', { 
                user, 
                pastes: userPastes,  // Send the user's pastes to the view
                pastesCount, 
                viewsCount, 
                isAuthenticated: !!req.session.userId 
            });
        } else {
            res.redirect('/login'); // Redirect to login if user not found
        }
    } catch (error) {
        console.error(error);
        res.redirect('/login'); // Redirect to login on error
    }
});



// index.js
// ... (previous code)

// Login route
app.get('/login', checkAuthenticated, (req, res) => {

  res.render('login', { error: null }); // Pass the error variable with a value of null
});


app.post('/login', async (req, res) => {
  const usernameLowercase = req.body.username.toLowerCase();
  const password = req.body.password;

  try {
      // Find user by the lowercase version of the username
      const user = await User.findOne({ usernameLowercase });
      
      if (user && await bcrypt.compare(password, user.password)) {
          req.session.userId = user._id;
          res.redirect('/');
      } else {
          res.render('login', { error: 'Invalid username or password' });
      }
  } catch (error) {
      console.error(error);
      res.render('login', { error: 'Error logging in' });
  }
});





// index.js
// ... (previous code)

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error(err);
    }
    res.redirect('/login');
  });
});

// Middleware to check if the user is an admin
async function checkAdmin(req, res, next) {
  if (req.session.userId) {
    try {
      const user = await User.findById(req.session.userId).exec();
      if (user && user.isAdmin) {
        return next(); // User is admin, proceed to the admin dashboard
      } else {
        return res.redirect('/'); // User is not an admin, redirect
      }
    } catch (err) {
      console.error(err);
      return res.redirect('/login');
    }
  } else {
    res.redirect('/login'); // User is not logged in, redirect to login page
  }
}

// Apply the middleware to admin routes
app.get('/admin/dashboard', checkAdmin, async (req, res) => {
    try {
        const usersCount = await User.countDocuments();
        const pastesCount = await Paste.countDocuments();

        res.render('adminDashboard', { 
            usersCount: usersCount, 
            pastesCount: pastesCount 
        });
    } catch (err) {
        console.error(err);
        res.status(500).send('Server Error');
    }
});



// Display a list of all pastes in the admin dashboard
app.get('/admin/pastes', checkAdmin, async (req, res) => {
  try {
    const pastes = await Paste.find().populate('userId'); // Fetch all pastes and populate user details
    res.render('adminPastes', { pastes }); 
  } catch (error) {
    console.error(error);
    res.status(500).send('Error fetching pastes');
  }
});

app.get('/admin/users', checkAdmin, async (req, res) => {
  try {
    const users = await User.find();
    res.render('adminUsers', { users });
  } catch (error) {
    console.error(error);
    res.status(500).send('Error fetching users');
  }
});

app.post('/admin/users/:user_id/toggleAdmin', checkAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.user_id);
    if (user) {
      user.isAdmin = !user.isAdmin; // Toggle admin status
      await user.save();
      res.redirect('/admin/users');
    } else {
      res.status(404).send('User not found');
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Error updating admin status');
  }
});


app.post('/admin/users/updateCSS', async (req, res) => {
  // You'll be iterating over all users to update their CSS
  for (let key in req.body) {
    if (key.startsWith('customCSS_')) {
      const userId = key.replace('customCSS_', '');
      const css = req.body[key];

      try {
        await User.findByIdAndUpdate(userId, { customCSS: css });
      } catch (error) {
        console.error(`Failed to update CSS for user ${userId}:`, error);
      }
    }
  }
  res.redirect('/admin/users');  // Redirect back to the admin users page
});




app.listen(3000, () => {
  console.log('Server started on http://localhost:3000');
});



app.set('view engine', 'ejs');


// Assuming you're using Express and have app set up

app.post('/admin/pastes/:id/delete', async (req, res) => {
    const pasteId = req.params.id;

    try {
        await Paste.deletePasteById(pasteId);
        res.redirect('/admin/pastes');  // Redirect back to the Manage Pastes page after deletion
    } catch (err) {
        console.error('Error deleting paste:', err);
        res.status(500).send('Server Error');
    }

});


app.get('/check-email', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.query.email });
        if (user) {
            res.json({ exists: true });
        } else {
            res.json({ exists: false });
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});


app.get('/check-username', async (req, res) => {
    try {
        const username = req.query.username;
        if (!username) {
            return res.json({ success: false, message: "Username not provided." });
        }

        const user = await User.findOne({ username });
        if (user) {
            return res.json({ exists: true }); // If the username exists in the database
        } else {
            return res.json({ exists: false }); // If the username does not exist in the database
        }
    } catch (error) {
        console.error("Error checking username:", error);
        return res.status(500).json({ success: false, message: "Server error." });
    }
});

app.get('/edit-profile', isAuthenticated, async (req, res) => {
  const userId = req.session.userId;
  try {
    const user = await User.findById(userId);
    if (user) {
      res.render('editProfile', { user });
    } else {
      res.redirect('/login'); // Redirect to login if user not found
    }
  } catch (error) {
    console.error(error);
    res.redirect('/login'); // Redirect to login on error
  }
});
const multer = require('multer');
const storage = multer.diskStorage({
  destination: 'public/uploads', 
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const extname = path.extname(file.originalname);
    cb(null, 'avatar-' + uniqueSuffix + extname);
  }
});

const upload = multer({ storage: storage });



const fs = require('fs').promises; // If you haven't already, import the promises version of fs

app.post('/edit-profile', isAuthenticated, upload.single('avatar'), async (req, res) => {
    const userId = req.session.userId;
    const { username, email } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.redirect('/login'); // Redirect to login if user not found
        }

        user.username = username;
        user.email = email;

        // Handle avatar update if a new file is uploaded
        if (req.file) {
            console.log("Uploaded File Details:", req.file);

            const avatarBuffer = await fs.readFile(req.file.path);
            console.log("Avatar Buffer Length:", avatarBuffer.length);

            user.avatar = {
                data: avatarBuffer,
                contentType: req.file.mimetype
            };
        }

        await user.save();
        console.log("User saved with avatar.");
        res.redirect('/profile');  // Redirect back to the profile page
    } catch (error) {
        console.error("Error:", error);
        res.redirect('/login'); // Redirect to login on error
    }
});

app.get('/user/:username', async (req, res) => {
    const username = req.params.username;

    try {
        const user = await User.findOne({ username: username });

        if (!user) {
            return res.status(404).send('User not found');
        }

        const pastes = await Paste.find({ userId: user._id });
        const views = pastes.reduce((total, paste) => total + (paste.views || 0), 0);

        res.render('publicProfile', { 
            user: user,
            pastesCount: pastes.length,
            views: views,
            isAuthenticated: !!req.session.userId 
        });

    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});



app.get('/my-pastes', isAuthenticated, async (req, res) => {
    const userId = req.session.userId;
    const currentPage = Number(req.query.page) || 1;
    const itemsPerPage = 5;

    try {
        const user = await User.findById(userId); // Fetch the user
        const totalPastes = await Paste.countDocuments({ userId: userId });
        const pastes = await Paste.find({ userId: userId })
                                .sort({ createdAt: -1 })
                                .skip((currentPage - 1) * itemsPerPage)
                                .limit(itemsPerPage);

        const totalPages = Math.ceil(totalPastes / itemsPerPage);
        res.render('my-pastes', { 
            pastes, 
            currentPage, 
            totalPages, 
            formatTimeAgo,
            isAuthenticated: !!req.session.userId,
            user  // Pass the user object to the view
        });
    } catch (error) {
        console.error(error);
        res.redirect('/login');
    }
});



function remove(pasteId) {
    fetch(`/delete/${pasteId}`, {
        method: 'DELETE',
    })
    .then(response => response.json())
    .then(data => {
        if(data.success) {
            alert('Paste deleted successfully!');
            location.reload();
        } else {
            alert('Error deleting paste!');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error deleting paste!');
    });
}




function remove(pasteId) {
    fetch(`/delete/${pasteId}`, {
        method: 'DELETE',
    })
    .then(response => response.json())
    .then(data => {
        if(data.success) {
            alert('Paste deleted successfully!');
            location.reload();
        } else {
            alert('Error deleting paste!');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert('Error deleting paste!');
    });
}



app.delete('/delete/:pasteId', isAuthenticated, async (req, res) => {
    const pasteId = req.params.pasteId;
    try {
        // You don't need to fetch the paste first if you just want to delete it
        const result = await Paste.deleteOne({ _id: pasteId, userId: req.session.userId });
        if (result.deletedCount > 0) {
            res.json({ success: true, message: 'Paste deleted successfully' });
        } else {
            res.status(403).json({success: false, message: 'guck'});
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Error deleting paste' });
    }
});






const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,  // 1 minute
  max: 30,                   // limit each IP to 1 request per minute
  message: "Too many requests from this IP, please try again later."
});


const apiTokens = ['AaA@9090', 'YOUR_API_TOKEN_2'];  // You can generate and store these however you like

function authenticateAPI(req, res, next) {
    const token = req.headers['x-api-token'];
    if (!apiTokens.includes(token)) {
        return res.status(403).json({ error: 'Invalid or missing API token.' });
    }
    next();
}



app.use('/api/', apiLimiter);  // Apply rate limiting to all API routes
app.use('/api/', authenticateAPI);  // Apply authentication to all API routes

// Create Paste
// Create Paste
app.post('/api/paste', async (req, res) => {
    const name = req.body.pasteName || "Untitled Paste"; 
    const content = req.body.content;
    const language = req.body.language || "plaintext"; 

    let expirationDate;
    switch (req.body.expiration) {
        case '10m':
            expirationDate = new Date(Date.now() + 10 * 60 * 1000);
            break;
        case '1h':
            expirationDate = new Date(Date.now() + 60 * 60 * 1000);
            break;
        case '1d':
            expirationDate = new Date(Date.now() + 24 * 60 * 60 * 1000);
            break;
        default:
            expirationDate = null;
            break;
    }

    const pasteData = {
        name,
        content,
        language,
        expiration: expirationDate,
        password: req.body.password ? req.body.password : null
    };

    if (req.session.userId) {
        pasteData.userId = req.session.userId;
    }

    const paste = new Paste(pasteData);

    try {
        await paste.save();
        res.json({ success: true, pasteId: paste._id });  
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Error saving paste' });
    }
});

// Retrieve Paste
app.get('/api/paste/:paste_id', async (req, res) => {
    const paste = await Paste.findById(req.params.paste_id);
    if (!paste) {
        return res.status(404).json({ error: 'Paste not found.' });
    }
    res.json(paste);
});

// Delete Paste
app.delete('/api/paste/:paste_id', async (req, res) => {
    const result = await Paste.findByIdAndDelete(req.params.paste_id);
    if (!result) {
        return res.status(404).json({ error: 'Paste not found.' });
    }
    res.json({ success: true, message: 'Paste deleted.' });
});

app.set('trust proxy', 1);
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static('public'));



// ... All your routes and other middlewares above ...

// Handle 404 - this middleware should be placed at the end
// ... 404 middleware above ...

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
});


// ... All your routes and other middlewares above ...

// Handle 404 - this middleware should be placed at the end
app.use((req, res) => {
    res.status(404).render('404');
});




