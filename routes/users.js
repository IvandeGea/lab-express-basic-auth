const router = require("express").Router();

const User = require("../models/User.model")

const bcrypt = require("bcryptjs");
const saltRounds = 10;

//vamos a requerir los middlewares
const isLoggedIn = require("../middleware/isLoggedIn")
const isLoggedOut = require("../middleware/isLoggedout")

/* GET home page */
router.get("/signup", (req, res, next) => {
  res.render("users/signup");
});

router.post("/signup", isLoggedOut, (req, res, next) => {

  //pillamos los datos del formulario del view
  let { username, password, passwordRepeat } = req.body;
  // Ahora comprobaremos que los campos que pone sean de formato o carac correctas con condicionales

  if (username == "" || password == "" || passwordRepeat == "") {
    res.render("users/signup", { mensajeError: "Falta completar campos" })
  }
  else if (password != passwordRepeat) {
    res.render("user/signup", { mensajeError: "Las contraseñas no coinciden" })

  }
  User.find({ username })
    .then(results => {
      console.log("results ", results);
      if (results.length != 0) { // COMPROBAMOS QUE NO HAY OTRO Nombre COMO ESTE

        res.render("users/signup", { mensajeError: "El usuario ya existe" });
        return;
      }
      //el usuario ha pasado las validaciones
      //proceso de encriptación con bcrypt: EL PASsWORD
      let salt = bcrypt.genSaltSync(saltRounds);
      let passwordEncriptado = bcrypt.hashSync(password, salt);

      User.create({
        username: username,
        password: passwordEncriptado
      })
        .then(result => {
          res.redirect("/user/login");
        })
        .catch(err => next(err))
    })
    .catch(err => {
      console.log("err ", err);
      next(err);
    })

})

// RUTA LOGIN
router.get("/login", (req, res, next) => {
  res.render("users/login");
});

router.post("/login", (req, res, next) => {

  let { username, password } = req.body;

  if (username == "" || password == "") {
    res.render("users/login", { mensajeError: "Completa los campos" });
    return;
  };

  User.find({ username })
    .then(results => {
      if (results.length == 0) {

        res.render("users/login", {
          mensajeError: "Datos Incorrectos"
        });

        return;

      }
      if (bcrypt.compareSync(password, results[0].password)) {
        req.session.currentUser = username;

        res.redirect("/user/profile");

      } else {
        res.render("user/login", {
          mensajeError: "Datos Incorrectos"

        });
      }
    })
    .catch(err => next(err));
})


router.get("/profile", (req, res, next) => {
  res.render("users/profile");
});

router.get("/", (req, res, next) => {
  res.render("index");
});

router.get("/privat", isLoggedIn, (req, res, next) => {
  res.render("users/private")
});

router.get("/main", isLoggedOut, (req, res, next) => {
  res.render("users/main")
});

router.get("/logout", isLoggedIn, (req, res, next) => {
  req.session.destroy(err => {
    if (err) next(err);
    else res.redirect("/user/login");
  });
});



module.exports = router;
