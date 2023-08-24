const User = require('./models/user.js'); // Replace with the actual path to your User model

module.exports = {
    isAuthenticated: async (req, res, next) => {
        console.log("Running isAuthenticated middleware");
        
        if (req.session.userId) {
            console.log("Session userId found:", req.session.userId);
            
            try {
                req.currentUser = await User.findById(req.session.userId);
                
                if (req.currentUser) {
                    console.log("User fetched:", req.currentUser);
                } else {
                    console.error("No user found with ID:", req.session.userId);
                }
                
                req.isAuthenticated = true;
            } catch (error) {
                console.error("Error fetching user:", error.message);
            }
        } else {
            console.log("No session userId found");
            req.isAuthenticated = false;
        }
        
        next();
    }
};
