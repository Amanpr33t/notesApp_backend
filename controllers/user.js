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

        //const isFirstAccount = await User.countDocuments({}) === 0
       // const role = isFirstAccount ? 'admin' : 'user'


       // const verificationToken = crypto.randomBytes(3).toString('hex')
        const user=await User.create({  email, password })
        const authToken = user.createJWT()
        res.status(StatusCodes.CREATED).json({ status: 'ok', msg:'Account has been created',authToken })

        //const verificationLink=`${origin}/user/verifyEmail?token=${verificationToken}&email=${email}`
        //const verificationMessage=`<a href="${verificationLink}">Verify Email</a>`


       /* const emailInput = {
            from: 'aman11865@gmail.com',
            to: email,
            subject: 'Email Confirmation',
            msg: `<h4>Hello, ${name}</h4>,your confirmation code for notesApp is ${verificationToken}`
        }
        await sendEmail(emailInput)*/


    } catch (error) {
        res.status(400).msg(error)
        throw new Error(error)
    }

}

/*const login=async(req,res)=>{
    const {email,password}=req.body
    if(!email || !password){
        throw new CustomAPIError('enter email and password ',400)
    }
    const user= await User.findOne({email}).populate('notes')
    if(!user){
        throw new CustomAPIError('invalid credentials ',401)
    }
    
    const isPasswordCorrect=await user.comparePassword(password)

    if(!isPasswordCorrect){
        throw new CustomAPIError('invalid credentials ',401)
    }
    if(!user.isVerified){
        throw new CustomAPIError('user nor verified' ,401)
    }
    //const token= user.createJWT()
    const tokenUser={
        name:user.name,
        userId:user._id,
        role:user.role
    }

     const token= createJWT({payload:tokenUser})
     //cookies part will be done later
     attachCookiesToResponse({res,token})
   // res.status(StatusCodes.CREATED).json({user:user.name,token})
    res.status(StatusCodes.CREATED).json({user:user.name,token,notes:user.notes})
    req.email=email
 }*/

const login = async (req, res) => {
    try {
        const { email, password } = req.body
        if (!email || !password) {
            res.status(StatusCodes.BAD_REQUEST).json({ msg: 'Please enter email and password' })
            throw new CustomAPIError('Please enter email and password ', 400)
        }
        //const user = await User.findOne({ email }).populate('notes')
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
       /* if (!user.isVerified) {
            const verificationToken = crypto.randomBytes(3).toString('hex')
            await User.findOneAndUpdate({ email },
                { verificationToken },
                { new: true, runValidators: true })
            const emailInput = {
                from: 'aman11865@gmail.com',
                to: email,
                subject: 'Email Confirmation',
                msg: `<h4>Hello, ${user.name}</h4>,your confirmation code for notesApp is ${verificationToken}`
            }
            await sendEmail(emailInput)

            res.status(StatusCodes.BAD_REQUEST).json({ status: 'notVerified', verificationToken: user.verificationToken })
            return
        }*/
        const authToken = user.createJWT()
        res.status(StatusCodes.OK).json({ status: 'ok', authToken })
        //use this for cookies method
        /*
        const tokenUser={
            name:user.name,
            userId:user._id,
            role:user.role
        }
        await refreshTokenCreator(req,res,tokenUser)*/
    } catch (error) {
        throw new Error(error)
    }

    /*let refreshToken
    const existingToken= await Token.find({user:user._id})
    
    if(existingToken && existingToken?.refreshToken){
        const {isValid}= existingToken
        if(!isValid){
            throw new CustomAPIError('invalid credentials',401)
        }
        refreshToken=existingToken.refreshToken
        attachCookiesToResponse({res,user:tokenUser,refreshToken})
        res.status(StatusCodes.OK).json({user:user.tokenUser})
        return
    }
    
     refreshToken= crypto.randomBytes(40).toString('hex')
    const userAgent= req.headers['user-agent']
    const ip= req.ip
    const userToken={
        refreshToken,
        ip,
        userAgent,
        user:user._id
    }
    await Token.create(userToken)


     //const token= createJWT({payload:tokenUser})
     //cookies part will be done later
     attachCookiesToResponse({res,user:tokenUser,refreshToken})
   // res.status(StatusCodes.CREATED).json({user:user.name,token})
    res.status(StatusCodes.CREATED).json({user:user.name,notes:user.notes})
    */
}

const forgotPassword = async (req, res) => {
    try {

        /*const { email: userEmail, token } = req.query
        if (userEmail && token) {
            const user = await User.findOne({ email: userEmail })
            if (!user) {
                res.status(StatusCodes.BAD_REQUEST).json({msg:'Wrong credentials'})
                throw new CustomAPIError('wrong credentials', 400)
            }
            if (token !== user.passwordToken) {
                res.status(StatusCodes.BAD_REQUEST).json({msg:'Wrong credentials'})
                throw new CustomAPIError('wrong credentials', 400)
            }
            if (user.passwordTokenExpirationDate.getTime() <= Date.now()) {
                res.status(StatusCodes.BAD_REQUEST).json({msg:'Session expired'})
                throw new CustomAPIError('session expired', 400)
            }
            await User.findOneAndUpdate({ email: userEmail },
                { forgotPasswordEnabler: true },
                { new: true, runValidators: true })
            //redirect to frontend where new password will be set
            res.redirect('https://www.geeksforgeeks.org')
            return
        }*/

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
        /*const resetURL = `${origin}/user/forgotPassword?token=${passwordToken}&email=${email}`
        const msg = `<p>Please reset password by clicking on the following link: <a href="${resetURL}">Reset password</a></p>`*/
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
        /*user.passwordToken=passwordToken
        user.passwordTokenExpirationDate=passwordTokenExpirationDate
        await user.save()*/
        await User.findOneAndUpdate({ email },
            { passwordToken, passwordTokenExpirationDate ,forgotPasswordEnabler: true},
            { new: true, runValidators: true })
        res.status(StatusCodes.OK).json({msg:'Check your email'})
    } catch (error) {
       throw new Error(error)
    }

}

const setForgotPassword = async (req, res) => {
    //const user = await User.findOne({ _id: req.user.userId })
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
        /* await User.findOneAndUpdate({_id:req.user.userId},req.body,{
          new:true,
          runValidators:true
        })*/
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
    //this didn't work
    //const user= User.findOne({_id:userId})
    //await user.remove()
    res.status(StatusCodes.OK).json({ msg: 'account deleted successfully' })
}

const verifyEmail = async (req, res) => {
    try {
        //this is used for frontend
        //const {email,verificationToken}= req.body
        //const {email,token:verificationToken}= req.query 
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
            //here redirect to frontend - add it
        }
        await User.findOneAndUpdate({ email },
            { verificationToken: '', verified: new Date(Date.now()), isVerified: true },
            { new: true, runValidators: true }
        )
        const updatedUser = await User.findOne({ email })
        if (updatedUser.isVerified) {
            const authToken = user.createJWT()
            res.status(StatusCodes.OK).json({ status: 'ok', isVerified: true, authToken })
            //use this for cookies method
            /* const tokenUser={
                 name:updatedUser.name,
                 userId:updatedUser._id,
                 role:updatedUser.role
             }
         await refreshTokenCreator(req,res,tokenUser)*/
        }
    } catch (error) {
        console.log(error)
    }

}

module.exports = {
    signup,
    login,
    forgotPassword,
    getAllUsers,
    changePassword,
    deleteUser,
    verifyEmail,
    setForgotPassword
}