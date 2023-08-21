// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: {
        type: Boolean,
        default: false
    },
    customCSS: {
       type: String,
       default: ""
    },
   avatar: {
        data: Buffer,
        contentType: String
    },

});

userSchema.pre('save', async function(next) {
    const user = this;
    if (!user.isModified('password')) return next();

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);
    next();
});

const User = mongoose.model('User', userSchema);

module.exports = User;
