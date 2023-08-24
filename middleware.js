const User = require('./models/user.js'); // Replace with the actual path to your User model

module.exports = {
    isAuthenticated: async (req, res, next) => {
        if (req.session.userId) {
            try {
                req.currentUser = await User.findById(req.session.userId);
                if (!req.currentUser) {
                    console.error("User not found with ID:", req.session.userId);
                }
                req.isAuthenticated = true;
            } catch (error) {
                console.error("Error fetching user:", error.message);
            }
        } else {
            req.isAuthenticated = false;
        }
        next();
    }
};
