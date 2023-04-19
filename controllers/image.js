const cloudinary = require('cloudinary').v2
const path = require('path')
const { StatusCodes } = require('http-status-codes')
const fs = require('fs')

const uploadImage = async (req, res) => {
    try {
        if (!req.files) {
            return
        }
        let image = req.files.image
        if (!image.mimetype.startsWith('image')) {
            return res.status(StatusCodes.BAD_REQUEST).json({
                status: 'invalid',
                msg: 'please add an image'
            })
        }
        const maxSize = 1024 * 1024
        if (image.size > maxSize) {
            return res.status(StatusCodes.BAD_REQUEST).json({
                status: 'too-large',
                msg: 'image should be smaller than 1MB'
            })
        }
        const result = await cloudinary.uploader.upload(
            req.files.image.tempFilePath,
            {
                use_filename: true,
                folder: 'notesApp-Images'
            }
        )
        fs.unlinkSync(req.files.image.tempFilePath)
        return res.status(StatusCodes.OK).json({
            status: 'ok',
            imagePath: { src: result.secure_url }
        })
    } catch (error) {
        throw new Error(error)
    }


}
module.exports = {
    uploadImage
}