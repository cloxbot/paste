const mongoose = require('mongoose');

const pasteSchema = new mongoose.Schema({
    name: String, 
    content: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    views: { type: Number, default: 0 },
    language: String,
    expiration: Date,
    password: String,
    viewedBySessions: [String],
}, {
    timestamps: true  // This should be inside the schema definition options
});

pasteSchema.statics.deletePasteById = async function(pasteId) {
    return this.deleteOne({ _id: pasteId }).exec();
}

module.exports = mongoose.model('Paste', pasteSchema);
