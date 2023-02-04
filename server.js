
/*============================[Modulos]============================*/

import express from "express"
import session from "express-session"
import exphbs from 'express-handlebars'
import path from 'path'
import bcrypt from 'bcrypt'

import dotenv from "dotenv"
dotenv.config()

import passport from "passport"
import { Strategy } from "passport-local"
const LocalStrategy = Strategy


/*----------- Base de datos -----------*/

import ContenedorMongoDb from "./src/contenedores/ContenedorMongoDb.js"
const usuariosDb = new ContenedorMongoDb("usuarios", {
        username: { type: String, required: true },
        password: { type: String, required: true },
        email: { type: String, required: true }
})




const app = express();





/*============================[Middlewares]============================*/

app.use(express.urlencoded({ extended: true }));
app.use(express.json());


/*----------- Passport -----------*/

passport.use(new LocalStrategy(
    async function (username, password, done) {
        console.log(`${username} ${password}`)

        //Logica para validar si un usuario existe
        await usuariosDb.listar(username).then(data=>{

            const usuarioEncontrado = data.find(usuario=> usuario.username == username)

            if(usuarioEncontrado){
                const userPassword = usuarioEncontrado.password
                const match = verifyPass(userPassword, password)
    
                if (!match) {
                    return done(null, false)
                }
                return done(null, data);
            }
            else{
                console.log("Usuario no encontrado en la DB")
                return done(null, false);
            }
        })
    }
))

passport.serializeUser((user, done)=> {
    const usuario = user[0]
    done(null, usuario.username);
})
  
passport.deserializeUser((username, done)=> {
    usuariosDb.listar(username).then(data=>{
        const usuarioEncontrado = data.find(usuario=> usuario.username == username)
        done(null, usuarioEncontrado);
    })
})



/*----------- Session -----------*/
app.use(session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
        maxAge: 600000 //10 min
    }
}))

app.use(passport.initialize())
app.use(passport.session())


// Metodos de Auth con Bcrypt
async function generateHashPassword(password) {
    const hashPassword = await bcrypt.hash(password, 10)
    return hashPassword
}

async function verifyPass(userPassword, password) {
    const match = await bcrypt.compare(password, userPassword)
    console.log(`pass login: ${password} || pass hash: ${userPassword}`)
    return match
}



function isAuth(req, res, next) {
    if (req.isAuthenticated()) {
        next()
    } else {
        res.redirect('/login')
    }
}


/*----------- Motor de plantillas -----------*/

app.set('views', 'src/views');
app.engine('.hbs', exphbs.engine({
    defaultLayout: 'main',
    layoutsDir: path.join(app.get('views'), 'layouts'),
    extname: '.hbs'
}));
app.set('view engine', '.hbs');






/*============================[Rutas]============================*/


app.get('/', (req, res) => {
    res.redirect('/login')
})


app.get('/login', (req, res) => {
    res.render('login.hbs');
})


app.get('/register', (req, res) => {
    res.render('registro.hbs');
})


app.post('/login', passport.authenticate('local', { successRedirect: '/datos', failureRedirect: '/login-error' }));






app.get('/datos', isAuth, (req, res) => {
    if (!req.user.contador) {
        req.user.contador = 1
    } else {
        req.user.contador++
    }
    const datosUsuario = {
        nombre: req.user.username,
        email: req.user.email
    }
    res.render('datos', { contador: req.user.contador, datos: datosUsuario });
})




app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    const newUser = { username: username, password: await generateHashPassword(password), email: email }

    await usuariosDb.listar(username).then(data=>{
        
        const usuarioEncontrado = data.find(usuario=> usuario.username == username)

        if(usuarioEncontrado){
            console.log("Usuario ya existente")
            res.redirect("/register-error")
        }else{
            console.log("Nuevo usuario creado")
            usuariosDb.guardar(newUser)
            res.redirect('/login')
        }

        
    })


})



app.get('/logout', (req, res) => {
    req.logOut(err => {
        res.redirect('/');
    });
})


app.get('/login-error', (req, res) => {
    res.render('login-error');
})

app.get('/register-error', (req, res) => {
    res.render('registro-error');
})



/*============================[Servidor]============================*/

const PORT = process.env.PORT;
const server = app.listen(PORT, () => {
    console.log(`Servidor escuchando en el puerto ${PORT}`);
})
server.on('error', error => {
    console.error(`Error en el servidor ${error}`);
});