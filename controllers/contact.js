/*const CustomAPIError = require("../errors/custom-error")
const sendEmail = require('../utils/sendEmail')
const contact = async (req, res) => {
    try {
        const { from, subject, msg } = req.body
        const emailContent = {
            from,
            to: process.env.ADMIN_EMAIL,
            subject,
            msg
        }
        sendEmail(emailContent)
        res.status(200).json({ status: 'ok', msg: 'Email has been sent' })
    } catch (error) {
        throw new Error(error)
    }

}
module.exports = contact*/