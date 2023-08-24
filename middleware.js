// middleware.js
module.exports = {
    isAuthenticated: async (req, res, next) => {
        if (req.session.userId) {
            try {
                req.currentUser = await User.findById(req.session.userId);
                req.isAuthenticated = true;
                next();
            } catch (error) {
                console.error("Error fetching user:", error.message);
                next(error);
            }
        } else {
            req.isAuthenticated = false;
            next();
        }
    }
};