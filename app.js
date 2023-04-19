const express = require('express')
const app= express()
app.use(express.static('./public'))
app.use(express.urlencoded({extended:false}))
app.use(express.json())
const userRouter= require('./routes/userRouter')
const notesRouter= require('./routes/notesRouter')
const imageRouter=require('./routes/imageRouter')
//const contactRouter=require('./routes/contactRouter')
const connectDB= require('./db/connect')
const port= process.env.PORT || 3033
const mongoose= require('mongoose')
mongoose.set('strictQuery', true)
require('dotenv').config()
const notFound= require('./middleware/notFound')
const errorHandlerMiddleware=require('./middleware/errorHandlerMiddleware')
const {authenticateUser,authorizePermissions}=require('./middleware/authentications')
const {getAllUsers}=require('./controllers/user')
const helmet=require('helmet')
const xss=require('xss-clean')
const rateLimit = require('express-rate-limit')
const fileUpload=require('express-fileupload')
const cloudinary= require('cloudinary').v2
const morgan= require('morgan')
const cookieParser= require('cookie-parser')
const mongoSanitize= require('express-mongo-sanitize')

cloudinary.config({
   cloud_name:process.env.CLOUD_NAME,
    api_key:process.env.CLOUD_API_KEY,
    api_secret:process.env.CLOUD_API_SECRET,
})

app.set('trust proxy',1)
app.use(
    rateLimit({
        windowMs:1000*60*60*24,
        max:100
    })
)

app.use(helmet())
const cors = require('cors');
app.use(cors())


app.use(xss())
app.use(fileUpload({useTempFiles:true}))
app.use(morgan('tiny'))
app.use(cookieParser(process.env.JWT_SECRET))
app.use(mongoSanitize())

app.use('/user',userRouter)
app.use('/notes',authenticateUser,notesRouter)
app.use('/image',imageRouter)
//app.use('/contact',authenticateUser,contactRouter)
app.use(notFound)
app.use(errorHandlerMiddleware)

const start=async()=>{
    try{
        await connectDB(process.env.MONGO_URI)
        app.listen(port,console.log(`server running on port ${port}...`))
    }catch(error){
        console.log(error)
    }
}
 start()  


