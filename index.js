// Servidor HTTP principal (Express) y configuración base
const express = require("express");
const backendPaciente = require("./backend/backend-paciente.js");
const backendMedico = require("./backend/backend-medico.js");
const backendAdmin = require("./backend/backend-admin.js");
const backendSuperAdmin = require("./backend/backend-super-admin.js");
const path = require("path");
const cookieParser = require("cookie-parser");

const aplicacion = express();

aplicacion.use(express.json());
aplicacion.use(cookieParser());

const puerto = process.env.PORT ?? 3000;

// Registrar backends de cada tipo de usuario
backendPaciente(aplicacion);
backendMedico(aplicacion);
backendAdmin(aplicacion);
backendSuperAdmin(aplicacion);

// Redireccionar accesos directos a algunos archivos HTML a la raíz
// para centralizar el inicio en index.html, pero permitir el login del paciente directamente
aplicacion.use((req, res, next) => {
    if (req.path === '/index.html' || req.path === '/login.html' || req.path === '/acceso.html' || req.path === '/acceso-paciente.html') {
        return res.redirect('/');
    }
    next();
});

//SERVIR ARCHIVOS ESTATICOS
aplicacion.use(express.static(path.join(__dirname, "public")));

//INICIAR SERVIDOR
aplicacion.listen(puerto, () => {
    console.log(`Server corriendo en ${puerto}`);
});
