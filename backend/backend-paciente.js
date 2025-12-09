const db = require("../connex.js");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const path = require("path");

const normalizarCorreo = (e) => String(e || '').trim().toLowerCase();
const esNoVacio = (v) => typeof v === 'string' && v.trim() !== '';
const esCorreoValido = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v || ''));
const esTelefonoValido = (v) => /^\d{11}$/.test(String(v || ''));
const esCedulaValida = (v) => /^\d{7,9}$/.test(String(v || ''));
const esSoloTexto = (v) => /^[A-Za-zÁÉÍÓÚáéíóúÑñ\s]+$/.test(String(v || ''));
const calcularHashMD5 = (texto) => crypto.createHash("md5").update(texto, "utf8").digest("hex");
const convertirCedulaNumero = (cedula) => {
    const numero = parseInt(String(cedula).trim(), 10);
    return isNaN(numero) || numero <= 0 ? null : numero;
};

const verificarToken = (req) => {
    try {
        return jwt.verify(req.cookies['access-token'], process.env.JWT_SECRET);
    } catch {
        return null;
    }
};

let cachePreguntasSeguridad = null;

const cargarPreguntasSeguridad = async () => {
    if (cachePreguntasSeguridad) return cachePreguntasSeguridad;
    const [filas] = await db.query(
        "SHOW COLUMNS FROM `pregunta_paciente` LIKE 'Pregunta'"
    );
    const tipoColumna = filas[0]?.Type || '';
    const coincidencia = tipoColumna.match(/^enum\((.*)\)$/i);
    if (!coincidencia) {
        cachePreguntasSeguridad = [];
        return cachePreguntasSeguridad;
    }
    cachePreguntasSeguridad = coincidencia[1]
        .split(/,(?=(?:[^']*'[^']*')*[^']*$)/)
        .map(v => v.trim().replace(/^'/, '').replace(/'$/, ''));
    return cachePreguntasSeguridad;
};

const validarRespuestas = async (cedula, respuestas) => {
    const [filasPreguntas] = await db.query(
        "SELECT `Respuesta` FROM `pregunta_paciente` WHERE `Usuario_Cedula` = ? AND `Status` = 1 ORDER BY `ID`",
        [cedula]
    );
    if (!filasPreguntas.length || filasPreguntas.length < 3) {
        return { valid: false, error: 'El usuario no tiene preguntas de seguridad configuradas.' };
    }
    for (let i = 0; i < 3; i++) {
        if (calcularHashMD5(respuestas[i]) !== filasPreguntas[i].Respuesta) {
            return { valid: false, error: `Las respuestas no coinciden en la pregunta ${i + 1}.` };
        }
    }
    return { valid: true };
};

module.exports = (app) => {

    app.get("/", (req, res) => {
        if (verificarToken(req)) return res.redirect("/acceso");
        // Página principal simple con enlaces a los distintos tipos de login
        res.sendFile(path.join(__dirname, "..", "public", "index.html"));
    });

    app.post("/register-check", async (req, res) => {
        const { correo, cedula } = req.body || {};
        if (!correo || !cedula) {
            return res.status(400).json({ error: "Faltan datos", field: !correo ? "correo" : "cedula" });
        }

        const correoNormalizado = normalizarCorreo(correo);
        if (!esCorreoValido(correoNormalizado)) {
            return res.status(400).json({ error: "Correo inválido.", field: "correo" });
        }

        const cedulaNum = convertirCedulaNumero(cedula);
        if (!cedulaNum || cedulaNum < 1000000 || cedulaNum > 999999999) {
            return res.status(400).json({ error: "Cédula inválida. Debe tener entre 7 y 9 dígitos.", field: "cedula" });
        }

        try {
            const [existingCedula] = await db.query("SELECT `Cedula` FROM `paciente` WHERE `Cedula` = ?", [cedulaNum]);
            if (existingCedula.length > 0) {
                return res.status(409).json({ error: "La cédula ingresada ya está registrada.", field: "cedula" });
            }

            const [existingCorreo] = await db.query("SELECT `Correo` FROM `paciente` WHERE `Correo` = ?", [correoNormalizado]);
            if (existingCorreo.length > 0) {
                return res.status(409).json({ error: "Ya existe un usuario con este correo.", field: "correo" });
            }

            return res.json({ success: true });
        } catch (error) {
            console.error("Error en /register-check:", error);
            return res.status(500).json({ error: "Error interno al validar datos." });
        }
    });

    app.post("/register", async (req, res) => {
        const { correo, sexo, nacionalidad, primerNombre, segundoNombre, primerApellido, segundoApellido, cedula, estado, municipio, password, confirmPassword, telefono, direccion, preguntas } = req.body || {};
    
        if (!correo || !sexo || !nacionalidad || !primerNombre || !primerApellido || !cedula || !estado || !municipio || !password || !confirmPassword || !telefono || !direccion) {
            return res.status(400).json({ error: "Faltan datos en el formulario." });
        }

        if (!preguntas || !Array.isArray(preguntas) || preguntas.length !== 3) {
            return res.status(400).json({ error: "Debe proporcionar 3 preguntas de seguridad con respuestas." });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ error: "Las contraseñas no coinciden." });
        }
    
        const correoNormalizado = normalizarCorreo(correo);
        if (!esCorreoValido(correoNormalizado)) return res.status(400).json({ error: "Correo inválido.", field: "correo" });
        if (!esCedulaValida(cedula)) return res.status(400).json({ error: "Cédula inválida. Debe tener entre 7 y 9 dígitos.", field: "cedula" });
        if (!esSoloTexto(primerNombre)) return res.status(400).json({ error: "El primer nombre solo debe contener letras.", field: "primerNombre" });
        if (!esNoVacio(primerNombre)) return res.status(400).json({ error: "Primer nombre requerido.", field: "primerNombre" });
        if (segundoNombre && !esSoloTexto(segundoNombre)) return res.status(400).json({ error: "El segundo nombre solo debe contener letras.", field: "segundoNombre" });
        if (!esSoloTexto(primerApellido)) return res.status(400).json({ error: "El primer apellido solo debe contener letras.", field: "primerApellido" });
        if (!esNoVacio(primerApellido)) return res.status(400).json({ error: "Primer apellido requerido.", field: "primerApellido" });
        if (segundoApellido && !esSoloTexto(segundoApellido)) return res.status(400).json({ error: "El segundo apellido solo debe contener letras.", field: "segundoApellido" });
        if (String(password).length < 6) return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres.", field: "password" });
        if (!esTelefonoValido(telefono)) return res.status(400).json({ error: "Teléfono inválido. Debe tener exactamente 11 dígitos.", field: "telefono" });
        if (!esNoVacio(direccion) || direccion.trim().length < 4) return res.status(400).json({ error: "Dirección requerida. Mínimo 4 caracteres.", field: "direccion" });
        if (!esNoVacio(estado)) return res.status(400).json({ error: "Estado requerido.", field: "estado" });
        if (!esNoVacio(municipio)) return res.status(400).json({ error: "Municipio requerido.", field: "municipio" });
        if (!['Masculino', 'Femenino'].includes(sexo)) return res.status(400).json({ error: "Sexo inválido.", field: "sexo" });
        if (!['Venezolano', 'Extranjero'].includes(nacionalidad)) return res.status(400).json({ error: "Nacionalidad inválida.", field: "nacionalidad" });

        const preguntaIds = preguntas.map(p => p.preguntaId);
        if (new Set(preguntaIds).size !== 3) {
            return res.status(400).json({ error: 'Debe seleccionar 3 preguntas distintas.' });
        }

        if (!preguntas.every(p => p.respuesta && p.respuesta.trim())) {
            return res.status(400).json({ error: 'Todas las preguntas deben tener respuesta.' });
        }

        const cedulaNum = convertirCedulaNumero(cedula);
        if (!cedulaNum || cedulaNum < 1000000 || cedulaNum > 999999999) {
            return res.status(400).json({ error: "Cédula inválida. Debe tener entre 7 y 9 dígitos.", field: "cedula" });
        }

        let conexion;
        try {
            conexion = await db.getConnection();
            await conexion.beginTransaction();
    
            await conexion.query(
                "INSERT INTO `paciente` (`Cedula`, `Correo`, `Nacionalidad`, `Primer_Nombre`, `Segundo_Nombre`, `Primer_Apellido`, `Segundo_Apellido`, `Telefono`, `Direccion`, `Estado`, `Municipio`, `Rol`, `Sexo`, `Status`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [cedulaNum, correoNormalizado, nacionalidad, primerNombre, segundoNombre || '', primerApellido, segundoApellido || '', telefono, direccion, estado, municipio, 'Paciente', sexo, 1]
            );
    
            await conexion.query(
                "INSERT INTO `lista_clave_paciente` (`paciente_Cedula`, `Clave`, `Status`) VALUES (?, ?, ?)",
                [cedulaNum, calcularHashMD5(password), 1]
            );

            const preguntasSeguridad = await cargarPreguntasSeguridad();

            for (const pregunta of preguntas) {
                const idPregunta = parseInt(pregunta.preguntaId, 10);
                if (isNaN(idPregunta) || idPregunta <= 0 || idPregunta > preguntasSeguridad.length) {
                    await conexion.rollback();
                    return res.status(400).json({ error: 'ID de pregunta inválido.' });
                }
                const preguntaTexto = preguntasSeguridad[idPregunta - 1];
                await conexion.query(
                    "INSERT INTO `pregunta_paciente` (`Pregunta`, `Usuario_Cedula`, `Respuesta`, `Status`) VALUES (?, ?, ?, ?)",
                    [preguntaTexto, cedulaNum, calcularHashMD5(pregunta.respuesta), 1]
                );
            }
    
            await conexion.commit();
            return res.status(201).json({ success: true, cedula: cedulaNum });
    
        } catch (error) {
            if (conexion) await conexion.rollback();
            console.error("Error en el registro:", error);
            if (error.code === 'ER_DUP_ENTRY') {
                const msg = String(error.sqlMessage || '').toLowerCase();
                if (msg.includes('correo')) return res.status(409).json({ error: "Ya existe un usuario con este correo.", field: "correo" });
                if (msg.includes('cedula') || msg.includes('primary')) return res.status(409).json({ error: "La cédula ingresada ya está registrada.", field: "cedula" });
            }
            return res.status(500).json({ error: "Error interno del servidor al registrar el usuario." });
        } finally {
            if (conexion) conexion.release();
        }
    });

    app.post("/login", async (req, res) => {
        const { correo, password } = req.body || {};
        if (!correo || !password) {
            return res.status(400).json({ error: "Faltan datos" });
        }

        const correoNormalizado = normalizarCorreo(correo);
        if (!esCorreoValido(correoNormalizado)) {
            return res.status(400).json({ error: "Correo inválido" });
        }
        if (String(password).length < 6) {
            return res.status(400).json({ error: "Contraseña inválida" });
        }

        try {
            const [rows] = await db.query(
                // Solo permitir login si el paciente está ACTIVO (Status = 1)
                "SELECT p.Cedula as cedula, p.Correo as correo, lc.Clave as password FROM paciente p JOIN lista_clave_paciente lc ON p.Cedula = lc.paciente_Cedula WHERE p.Correo = ? AND lc.Status = 1 AND p.Status = 1",
                [correoNormalizado]
            );
            
            const usuario = rows[0];
            if (!usuario || calcularHashMD5(password) !== usuario.password) {
                return res.status(401).json({ error: "Credenciales inválidas" });
            }
            
            const token = jwt.sign({ cedula: usuario.cedula, correo: usuario.correo }, process.env.JWT_SECRET, { expiresIn: '1h' });
            
            res.cookie('access-token', token, {
                httpOnly: true,
                sameSite: 'Strict',
                maxAge: 3600000,
                secure: process.env.NODE_ENV === 'production'
            });

            res.json({ success: true, cedula: usuario.cedula });
        } catch (error) {
            console.error("Error en el login:", error);
            res.status(500).json({ error: "Error al autenticar" });
        }
    });

    app.post('/recover-lookup', async (req, res) => {
        const { correo, cedula } = req.body || {};
        if (!correo || !cedula) {
            return res.status(400).json({ error: 'Faltan datos', found: false });
        }
        try {
            const correoNormalizado = normalizarCorreo(correo);
            const cedulaNum = convertirCedulaNumero(cedula);
            if (!cedulaNum) {
                return res.status(400).json({ error: 'Cédula inválida', found: false });
            }
            const [rows] = await db.query(
                // Solo permitir recuperación si el paciente está ACTIVO (Status = 1)
                "SELECT p.Cedula as cedula FROM paciente p WHERE p.Correo = ? AND p.Cedula = ? AND p.Status = 1",
                [correoNormalizado, cedulaNum]
            );
            if (!rows.length) {
                return res.status(404).json({ error: 'Usuario no encontrado o inactivo', found: false });
            }
            
            const [preguntasRows] = await db.query(
                "SELECT ID as id, Pregunta as pregunta FROM pregunta_paciente WHERE Usuario_Cedula = ? AND Status = 1 ORDER BY ID",
                [cedulaNum]
            );
            
            if (!preguntasRows.length || preguntasRows.length < 3) {
                return res.status(404).json({ error: 'El usuario no tiene preguntas de seguridad configuradas', found: false });
            }
            
            return res.json({ 
                success: true, 
                found: true, 
                cedula: rows[0].cedula,
                questions: preguntasRows.map((p, idx) => ({ id: p.id, pregunta: p.pregunta, posicion: idx + 1 }))
            });
        } catch (e) {
            console.error("Error en recover-lookup:", e);
            return res.status(500).json({ error: 'Error al buscar usuario', found: false });
        }
    });

    app.post('/verify-answers', async (req, res) => {
        const { cedula, respuestas } = req.body || {};
        
        if (!cedula || !respuestas || !Array.isArray(respuestas) || respuestas.length !== 3) {
            return res.status(400).json({ error: 'Faltan datos requeridos.' });
        }

        const usuarioCedula = convertirCedulaNumero(cedula);
        if (!usuarioCedula) {
            return res.status(400).json({ error: 'Cédula inválida.' });
        }

        try {
            const resultadoValidacion = await validarRespuestas(usuarioCedula, respuestas);
            if (!resultadoValidacion.valid) {
                return res.status(resultadoValidacion.error.includes('coinciden') ? 401 : 404).json({ error: resultadoValidacion.error });
            }
            return res.status(200).json({ success: true, message: 'Respuestas correctas.' });
        } catch (error) {
            console.error("Error en verify-answers:", error);
            return res.status(500).json({ error: 'Error al verificar las respuestas.' });
        }
    });

    app.post('/recover-password', async (req, res) => {
        const { cedula, respuestas, nuevaPassword, confirmPassword } = req.body || {};
        
        if (!cedula || !respuestas || !Array.isArray(respuestas) || respuestas.length !== 3 || !nuevaPassword || !confirmPassword) {
            return res.status(400).json({ error: 'Faltan datos requeridos.' });
        }
        
        if (nuevaPassword !== confirmPassword) {
            return res.status(400).json({ error: 'Las contraseñas no coinciden.' });
        }
        
        if (String(nuevaPassword).length < 6) {
            return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres.' });
        }

        const usuarioCedula = convertirCedulaNumero(cedula);
        if (!usuarioCedula) {
            return res.status(400).json({ error: 'Cédula inválida.' });
        }

        const nuevaHash = calcularHashMD5(nuevaPassword);

        let conexion;
        try {
            conexion = await db.getConnection();
            await conexion.beginTransaction();

            const resultadoValidacion = await validarRespuestas(usuarioCedula, respuestas);
            if (!resultadoValidacion.valid) {
                await conexion.rollback();
                return res.status(resultadoValidacion.error.includes('coinciden') ? 401 : 404).json({ error: resultadoValidacion.error });
            }

            // Verificar que la nueva contraseña no coincida con ninguna contraseña anterior (actual o histórica)
            const [clavesPrevias] = await conexion.query(
                "SELECT 1 FROM `lista_clave_paciente` WHERE `paciente_Cedula` = ? AND `Clave` = ? UNION SELECT 1 FROM `historico_clave_paciente` h JOIN `lista_clave_paciente` l ON h.`Lista_ID` = l.`ID` WHERE l.`paciente_Cedula` = ? AND h.`Clave` = ? LIMIT 1",
                [usuarioCedula, nuevaHash, usuarioCedula, nuevaHash]
            );

            if (clavesPrevias.length > 0) {
                await conexion.rollback();
                return res.status(400).json({ error: 'La nueva contraseña no puede ser igual a alguna de las contraseñas anteriores.' });
            }

            const [claveActual] = await conexion.query(
                "SELECT `ID`, `Clave` FROM `lista_clave_paciente` WHERE `paciente_Cedula` = ? AND `Status` = 1",
                [usuarioCedula]
            );

            if (!claveActual.length) {
                await conexion.rollback();
                return res.status(404).json({ error: 'No se encontró una clave activa para el usuario.' });
            }

            await conexion.query(
                "UPDATE `lista_clave_paciente` SET `Status` = 0 WHERE `paciente_Cedula` = ? AND `Status` = 1",
                [usuarioCedula]
            );

            await conexion.query(
                "INSERT INTO `historico_clave_paciente` (`Lista_ID`, `Clave`, `Status`) VALUES (?, ?, ?)",
                [claveActual[0].ID, claveActual[0].Clave, 0]
            );

            await conexion.query(
                "INSERT INTO `lista_clave_paciente` (`paciente_Cedula`, `Clave`, `Status`) VALUES (?, ?, ?)",
                [usuarioCedula, nuevaHash, 1]
            );

            await conexion.commit();
            return res.status(200).json({ success: true, message: 'Contraseña actualizada correctamente.' });

        } catch (error) {
            if (conexion) await conexion.rollback();
            console.error("Error en recover-password:", error);
            return res.status(500).json({ error: 'Error al recuperar la contraseña.' });
        } finally {
            if (conexion) conexion.release();
        }
    });

    app.get('/estados', async (req, res) => {
        try {
            const [rows] = await db.query("SELECT `id_estado`, `estado` FROM `estados` ORDER BY `estado`");
            return res.json({ estados: rows });
        } catch (e) {
            console.error("Error en /estados:", e);
            return res.status(500).json({ error: 'Error al obtener estados' });
        }
    });

    app.get('/municipios', async (req, res) => {
        const { estado } = req.query || {};
        if (!estado) {
            return res.status(400).json({ error: 'Debe proporcionar el parámetro estado' });
        }
        try {
            const [estadoRows] = await db.query(
                "SELECT `id_estado` FROM `estados` WHERE `estado` = ?",
                [estado]
            );
            
            if (!estadoRows.length) {
                return res.status(404).json({ error: 'Estado no encontrado', municipios: [] });
            }
            
            const idEstado = estadoRows[0].id_estado;
            const [rows] = await db.query(
                "SELECT `municipio` FROM `municipios` WHERE `id_estado` = ? ORDER BY `municipio`",
                [idEstado]
            );
            
            return res.json({ municipios: rows });
        } catch (e) {
            console.error("Error en /municipios:", e);
            return res.status(500).json({ error: 'Error al obtener municipios' });
        }
    });

    app.get('/preguntas', async (req, res) => {
        try {
            const preguntasEnumeradas = await cargarPreguntasSeguridad();
            if (!preguntasEnumeradas.length) {
                return res.status(500).json({ error: 'No se pudo obtener el catálogo de preguntas.' });
            }
            const preguntas = preguntasEnumeradas.map((texto, indice) => ({
                id: indice + 1,
                pregunta: texto
            }));
            return res.json({ preguntas });
        } catch (e) {
            console.error('Error en /preguntas:', e);
            return res.status(500).json({ error: 'Error al obtener preguntas de seguridad' });
        }
    });


    app.get('/me', async (req, res) => {
        const usuarioSesion = verificarToken(req);
        if (!usuarioSesion) return res.status(403).json({ error: 'No autorizado' });
        try {
            const [rows] = await db.query(
                // Validar también que el paciente siga ACTIVO al consultar su perfil
                "SELECT p.Primer_Nombre as primerNombre, p.Segundo_Nombre as segundoNombre, p.Primer_Apellido as primerApellido, p.Segundo_Apellido as segundoApellido, p.Correo as correo FROM paciente p WHERE p.Cedula = ? AND p.Status = 1",
                [usuarioSesion.cedula]
            );
            const perfil = rows[0];
            if (!perfil) return res.status(404).json({ error: 'Usuario no encontrado o inactivo' });
            const nombre = `${perfil.primerNombre} ${perfil.segundoNombre || ''} ${perfil.primerApellido} ${perfil.segundoApellido || ''}`.trim();
            return res.json({ nombre, correo: perfil.correo });
        } catch (e) {
            console.error("Error en /me:", e);
            return res.status(500).json({ error: 'Error al obtener perfil' });
        }
    });

    app.get("/acceso", (req, res) => {
        const usuarioSesion = verificarToken(req);
        if (!usuarioSesion) return res.status(403).json({ error: "No autorizado" });
        res.set({
            'Cache-Control': 'no-store, no-cache, must-revalidate, private',
            'Pragma': 'no-cache',
            'Expires': '0'
        });
        res.sendFile(path.join(__dirname, "..", "public", "acceso-paciente.html"));
    });

    app.post("/logout", (req, res) => {
        res.clearCookie('access-token');
        res.json({ success: true });
    });
}
