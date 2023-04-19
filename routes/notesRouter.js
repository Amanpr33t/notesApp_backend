const express= require('express')
const router= express.Router()
const {addNote,getNote,getAllNotes,deleteNote,editNote,deleteSelectedNotes}= require('../controllers/notes')
const {authenticateUser}=require('../middleware/authentications')


router.post('/addNote',authenticateUser,addNote)
router.get('/getAllNotes',authenticateUser,getAllNotes)
//router.delete('/deleteAllNotes',authenticateUser,deleteAllNotes)
router.get('/getNote/:id',authenticateUser,getNote)
router.delete('/deleteNote/:id',authenticateUser,deleteNote)
router.patch('/editNote/:id',authenticateUser,editNote)
router.delete('/deleteSelectedNotes/:id',authenticateUser,deleteSelectedNotes)

module.exports= router