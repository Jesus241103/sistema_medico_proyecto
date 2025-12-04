// Servidor HTTP principal (Express) y configuración base
const express = require("express");
const apis = require("./endpoints.js"); 
const path = require("path");
const cookieParser = require("cookie-parser");

const app = express();

app.use(express.json());
app.use(cookieParser());

const port = process.env.PORT ?? 3000;

//IMPORTAR RUTAS DESDE endpoints.js
apis(app);

// Redireccionar accesos directos a archivos HTML a la raíz
// para que siempre se pase por la lógica de autenticación
app.use((req, res, next) => {
    if (req.path === '/index.html' || req.path === '/login.html' || req.path === '/acceso.html') {
        return res.redirect('/');
    }
    next();
});

//SERVIR ARCHIVOS ESTATICOS
app.use(express.static(path.join(__dirname, "public")));

//INICIAR SERVIDOR
app.listen(port, () => {
    console.log(`Server corriendo en ${port}`);
});
