
const CustomAPIError = require('../errors/custom-error')
const Note = require('../models/note')
const { StatusCodes } = require('http-status-codes')


const addNote = async (req, res) => {
    try {
        req.body.createdBy = req.user.userId
        const { heading, content, image } = req.body
        if (content.trim() === '' || heading.trim() === '') {
            res.status(StatusCodes.NO_CONTENT).json({ status: 'failed', msg: 'Add content and heading' })
            throw new CustomAPIError('Add content and heading', 204)
        } else {
            const note = Note.create(req.body)
            return res.status(StatusCodes.CREATED).json({ status: 'ok', msg: 'Note has been added successfully' })
        }
    } catch (error) {
        throw new Error(error)
    }


}

const getNote = async (req, res) => {
    try {
        const userId = req.user.userId
        const noteId = req.params.id
        /*const note = await Note.findOne({
            _id: noteId,
            createdBy: userId
        }).populate({
            path: 'createdBy',
            select: 'name email'
        })*/
        const note = await Note.findOne({
            _id: noteId,
            createdBy: userId
        })
        if (!note) {
            throw new CustomAPIError('note not found', 404)
        }
        return res.status(StatusCodes.OK).json({ status: 'ok', note })
    } catch (error) {
        throw new Error(error)
    }

}

const getAllNotes = async (req, res) => {
    try {
        /* const allNotes = await Note.find({
         createdBy: req.user.userId
     }).sort('createdAt').populate({
         path: 'createdBy',
         select: 'name email'
     })*/
        const allNotes = await Note.find({
            createdBy: req.user.userId
        }).sort({ createdAt: -1 })
        return res.status(StatusCodes.OK).json({ status: 'ok', count: allNotes.length, allNotes })
    } catch (error) {
        throw new Error(error)
    }

}

const deleteNote = async (req, res) => {
    try {
        const note = await Note.findOne({
            _id: req.params.id,
            createdBy: req.user.userId
        })
        if (!note) {
            res.status(StatusCodes.NO_CONTENT).json({ msg: 'Note not found' })
            throw new CustomAPIError('Note not found', 204)
        }
        note.remove()
        return res.status(StatusCodes.OK).send({ status: 'ok', msg: 'Note has been removed' })
    } catch (error) {
        throw new Error(error)
    }

}

const deleteSelectedNotes = async (req, res) => {
    try {
        const ids = req.params.id.split('$')
        const newIds = ids.splice(1, ids.length)
        newIds.forEach(async (id) => {
            const note = await Note.findOne({ _id: id, createdBy: req.user.userId })
            if (note) {
                await Note.findOneAndDelete({ _id: id, createdBy: req.user.userId })
            }

        });
        return res.status(StatusCodes.OK).json({ status: 'ok', msg: 'All selected notes have been successfully deleted' })
    } catch (error) {
        throw new Error(error)
    }

}

/*const deleteAllNotes = async (req, res) => {
    try {
        const notes = await Note.find({ createdBy: req.user.userId })
        if (notes.length === 0) {
            req.status(CustomAPIError.NO_CONTENT).json({ msg: 'Notes not found' })
            throw new CustomAPIError('notes not found', 404)
        }
        await Note.deleteMany({
            createdBy: req.user.userId
        })
        res.status(StatusCodes.OK).send({ status: 'ok', msg: 'notes have been removed' })
    } catch (error) {
        throw new Error(error)
    }

}*/

const editNote = async (req, res) => {
    try {
        const {
            body: { heading, content, image },
            user: { userId },
            params: { id: noteId }
        } = req
        if (!content || !heading || content.trim() === '' || heading.trim() === '') {
            res.status(StatusCodes.BAD_REQUEST).json({ msg: 'No content and heading' })
            throw new CustomAPIError('give content and heading', 400)
        }
        const note = await Note.findOne({ _id: noteId, createdBy: userId })
        if (!note) {
            res.status(StatusCodes.BAD_REQUEST).json({ msg: 'Note not found' })
            throw new CustomAPIError('note not found', 204)
        }
        const updatedNote = await Note.findOneAndUpdate({
            _id: noteId,
            createdBy: userId
        },
            req.body,
            { new: true, runValidators: true })
        return res.status(StatusCodes.OK).json({ status: 'ok', msg: 'note has been updated', updatedNote })
    } catch (error) {
        throw new Error(error)
    }
    
}
module.exports = {
    addNote,
    getNote,
    getAllNotes,
    deleteNote,
    editNote,
    //deleteAllNotes,
    deleteSelectedNotes
}
