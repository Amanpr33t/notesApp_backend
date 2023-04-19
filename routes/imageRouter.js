const express= require('express')
const router= express.Router()
const {uploadImage}= require('../controllers/image')

router.post('/uploadImage',uploadImage)

module.exports= router