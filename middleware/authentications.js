const User = require('../models/user')
const jwt = require('jsonwebtoken')
const CustomAPIError = require('../errors/custom-error')
require('dotenv').config()
const { isTokenValid, attachCookiesToResponse } = require('../utils/jwt')
const Token = require('../models/Token')
const { StatusCodes } = require('http-status-codes')

//authentication with headers
const authenticateUser = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            res.status(StatusCodes.BAD_REQUEST).json({ msg: 'Authorization invalid' })
            throw new CustomAPIError('authorization invalid', 401)
        }
        const token = authHeader.split(' ')[1]

        const payload = jwt.verify(token, process.env.JWT_SECRET)

        if (!payload) {
            res.status(StatusCodes.BAD_REQUEST).json({ msg: 'Authorization invalid' })
            throw new Error('authentication invalid', 401)
        }

        const user = await User.findOne({ _id: payload.userId })
        if (!user) {
            res.status(StatusCodes.BAD_REQUEST).json({ msg: 'Authorization invalid' })
            throw new Error('authentication invalid', 401)
        }
        req.user = {
            userId: payload.userId,
            name: payload.name
            // role:payload.role
        }
        //req.user=payload.user
        next()
    } catch (error) {
        throw new Error(error)
    }
}
//authenticateUser with cookies
/*const authenticateUser=async(req,res,next)=>{
    try{
    const {refreshToken,accessToken}= req.signedCookies
        
        if(accessToken){
            const payload= isTokenValid(accessToken)
            if(!payload){
                throw new Error('authentication invalid',401)
            }
            const user= await User.findOne({_id:payload.user.userId})
            if(!user){
                throw new Error('authentication invalid',401)
            }
            req.user= payload.user
            return next()
        }
        const payload= isTokenValid(refreshToken)
        if(!payload){
            throw new Error('authentication invalid',401)
        }
        const user= await User.findOne({_id:payload.user.userId})
            if(!user){
                throw new Error('authentication invalid',401)
            }
        req.user=payload.user
        next()
    }catch(error){
        console.log(error)
        throw new CustomAPIError('Authentication invalid',401)
    }
}*/

const authorizePermissions = (req, res, next) => {
    if (req.user.role !== 'admin') {
        throw new CustomAPIError('unauthorized user', 401)
    }
    next()
}

module.exports = {
    authenticateUser, authorizePermissions
}