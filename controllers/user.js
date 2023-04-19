require('express-async-errors')
const { StatusCodes } = require('http-status-codes')
const User = require('../models/user')
const Note = require('../models/note')
const Token = require('../models/Token')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const CustomAPIError = require('../errors/custom-error')
const nodemailer = require('nodemailer')
const { createJWT, attachCookiesToResponse } = require('../utils/jwt')
const refreshTokenCreator = require('../utils/refreshTokenCreator')
const { findOneAndDelete } = require('../models/note')
const crypto = require('crypto')
const sendEmail = require('../utils/sendEmail')
const origin = process.env.ORIGIN

const signup = async (req, res) => {
    try {
        const {  email, password } = req.body
        if (!email || !password) { 
            res.status(StatusCodes.BAD_REQUEST).json({msg:'Please enter email and password'})
            throw new CustomAPIError('Please enter email and password', 400)
        }
        const emailExists = await User.findOne({ email })
        if (emailExists) {
            res.status(StatusCodes.BAD_REQUEST).json({ status:'emailExists',msg: 'Email already exists' })
            throw new CustomAPIError('email already exists', 400)
        }
        const user=await User.create({  email, password })
        const authToken = user.createJWT()
        return res.status(StatusCodes.CREATED).json({ status: 'ok', msg:'Account has been created',authToken })

    } catch (error) {
        throw new Error(error)
    }

}


const login = async (req, res) => {
    try {
        const { email, password } = req.body
        if (!email || !password) {
            res.status(StatusCodes.BAD_REQUEST).json({ msg: 'Please enter email and password' })
            throw new CustomAPIError('Please enter email and password ', 400)
        }
        const user = await User.findOne({ email })
        if (!user) {
            res.status(StatusCodes.BAD_REQUEST).json({status:'invalid', msg:'Invalid credentials' })
            throw new CustomAPIError('Invalid credentials ', 401)

        }

        const isPasswordCorrect = await user.comparePassword(password)

        if (!isPasswordCorrect) {
            res.status(StatusCodes.BAD_REQUEST).json({status:'invalid',msg:'Invalid credentials' })
            throw new CustomAPIError('Invalid credentials', 401)
        }
        const authToken = user.createJWT()
        return res.status(StatusCodes.OK).json({ status: 'ok', authToken })
    } catch (error) {
        throw new Error(error)
    }
}

/*const forgotPassword = async (req, res) => {
    try {

        const { email } = req.body
        if (!email) {
            res.status(StatusCodes.BAD_REQUEST).json({msg:'Please provide email'})
            throw new CustomAPIError('please provide email', 400)
        }
        const user = await User.findOne({ email })
        if (!user) {
            res.status(StatusCodes.BAD_REQUEST).json({msg:'Wrong credentials'})
            throw new CustomAPIError('wrong credentials', 400)
        }
        const passwordToken = crypto.randomBytes(3).toString('hex')
        const msg=`<p>Authentication token for password updation is <h1>${passwordToken}</h2></p>`
        const emailData = {
            from: process.env.ADMIN_EMAIL,
            to: email,
            subject: "Password change",
            msg
        }
        sendEmail(emailData)

        const tenMinutes = 1000 * 60 * 10
        const passwordTokenExpirationDate = new Date(Date.now() + tenMinutes)
        await User.findOneAndUpdate({ email },
            { passwordToken, passwordTokenExpirationDate ,forgotPasswordEnabler: true},
            { new: true, runValidators: true })
       return res.status(StatusCodes.OK).json({msg:'Check your email'})
    } catch (error) {
       throw new Error(error)
    }

}

const setForgotPassword = async (req, res) => {
    const { email,password,passwordToken } = req.body
    const user = await User.findOne({ email,passwordToken })
    if(!user){
        res.status(StatusCodes.BAD_REQUEST).json({msg:'No user exists'})
        throw new CustomAPIError('No user exists', 400)
    }
    if (!user.forgotPasswordEnabler || user.passwordToken!==passwordToken) {
        res.status(StatusCodes.BAD_REQUEST).json({msg:'access denied'})
        throw new CustomAPIError('access denied', 400)
    }
    if (user.passwordTokenExpirationDate.getTime() <= Date.now()) {
        res.status(StatusCodes.BAD_REQUEST).json({msg:'Session expired'})
        throw new CustomAPIError('session expired', 400)
    }
    user.password = password
    user.passwordToken=null
    user.passwordTokenExpirationDate=null
    user.forgotPasswordEnabler = false
    await user.save()
    res.status(StatusCodes.OK).json({ status: 'ok', msg: 'password updated successfully' })
}

const getAllUsers = async (req, res) => {
    try {
        const users = await User.find({ role: 'user' }).select('-password')
        res.status(StatusCodes.OK).json({ status: 'ok', users })
    } catch (error) {
        throw new Error(error)
    }
   
}

const changePassword = async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body
        if (!oldPassword || !newPassword) {
            res.status(StatusCodes.BAD_REQUEST).json({msg:'Enter passwords'})
            throw new CustomAPIError('enter passwords ', 400)
        }
        const user = await User.findOne({ _id: req.user.userId })

        const isPasswordCorrect = await user.comparePassword(oldPassword)
        if (!isPasswordCorrect) {
            res.status(StatusCodes.BAD_REQUEST).json({msg:'Invalid credentials'})
            throw new CustomAPIError('invalid credentials', 401)
        }
        user.password = newPassword
        await user.save()
        res.status(StatusCodes.OK).json({ status: 'ok', msg: 'Password successfully updated' })
    } catch (error) {
        console.log(error)
    }

}

const deleteUser = async (req, res) => {
    const { userId } = req.user
    const user = await User.findOne({ _id: userId })
    if (user.role === 'admin') {
        throw new CustomAPIError('action not allowed on this account', 400)
    }
    await User.findOneAndDelete({ _id: userId })
    await Note.deleteMany({ createdBy: userId })
    res.status(StatusCodes.OK).json({ msg: 'account deleted successfully' })
}

const verifyEmail = async (req, res) => {
    try {
        const { email, token: verificationToken } = req.body
        const user = await User.findOne({ email })
        if (!user) {
            res.status(StatusCodes.BAD_REQUEST).json({ status: 'failed', msg: 'user could not be verified' })
            throw new CustomAPIError('Verification failed', 204)
        }
        if (verificationToken !== user.verificationToken) {
            res.status(StatusCodes.BAD_REQUEST).json({ status: 'failed', msg: 'user could not be verified' })
            throw new CustomAPIError('verification failed', 401)

        }
        if (user.isVerified) {
            throw new CustomAPIError('user already verified', 400)
        }
        await User.findOneAndUpdate({ email },
            { verificationToken: '', verified: new Date(Date.now()), isVerified: true },
            { new: true, runValidators: true }
        )
        const updatedUser = await User.findOne({ email })
        if (updatedUser.isVerified) {
            const authToken = user.createJWT()
            res.status(StatusCodes.OK).json({ status: 'ok', isVerified: true, authToken })
        }
    } catch (error) {
        console.log(error)
    }

}*/

module.exports = {
    signup,
    login,
    /*forgotPassword,
    getAllUsers,
    changePassword,
    deleteUser,
    verifyEmail,
    setForgotPassword*/
}