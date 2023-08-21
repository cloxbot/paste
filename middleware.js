// middleware.js
module.exports = {
    isAuthenticated: (req, res, next) => {
        if (req.session.userId) {
            req.isAuthenticated = true;  // Add a flag indicating authentication
            next();
        } else {
            res.redirect("/")
            req.isAuthenticated = false; // Add a flag indicating no authentication
            next();
        }
    }
};
