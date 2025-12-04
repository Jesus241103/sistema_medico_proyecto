const db = require("./connex.js");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const path = require("path");

const normalizeCorreo = (e) => String(e || '').trim().toLowerCase();
const isNonEmpty = (v) => typeof v === 'string' && v.trim() !== '';
const isEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(v || ''));
const isPhone = (v) => /^\d{11}$/.test(String(v || ''));
const isCedula = (v) => /^\d{7,9}$/.test(String(v || ''));
const isTextOnly = (v) => /^[A-Za-zÁÉÍÓÚáéíóúÑñ\s]+$/.test(String(v || ''));
const hashMD5 = (text) => crypto.createHash("md5").update(text, "utf8").digest("hex");
const parseCedula = (cedula) => {
    const num = parseInt(String(cedula).trim(), 10);
    return isNaN(num) || num <= 0 ? null : num;
};

const verifyToken = (req) => {
    try {
        return jwt.verify(req.cookies['access-token'], process.env.JWT_SECRET);
    } catch {
        return null;
    }
};

const validateAnswers = async (cedula, respuestas) => {
    const [preguntasRows] = await db.query(
        "SELECT `Respuesta` FROM `pregunta_usuario` WHERE `Usuario_Cedula` = ? AND `Status` = 1 ORDER BY `Posicion`",
        [cedula]
    );
    if (!preguntasRows.length || preguntasRows.length < 3) {
        return { valid: false, error: 'El usuario no tiene preguntas de seguridad configuradas.' };
    }
    for (let i = 0; i < 3; i++) {
        if (hashMD5(respuestas[i]) !== preguntasRows[i].Respuesta) {
            return { valid: false, error: `Las respuestas no coinciden en la pregunta ${i + 1}.` };
        }
    }
    return { valid: true };
};

module.exports = (app) => {

    app.get("/", (req, res) => {
        if (verifyToken(req)) return res.redirect("/acceso");
        res.sendFile(path.join(__dirname, "public", "login.html"));
    });

    app.post("/register", async (req, res) => {
        const { correo, tipoPersona, nacionalidad, primerNombre, segundoNombre, primerApellido, segundoApellido, cedula, estado, municipio, password, confirmPassword, telefono, direccion, preguntas } = req.body || {};
    
        if (!correo || !tipoPersona || !nacionalidad || !primerNombre || !primerApellido || !cedula || !estado || !municipio || !password || !confirmPassword || !telefono || !direccion) {
            return res.status(400).json({ error: "Faltan datos en el formulario." });
        }

        if (!preguntas || !Array.isArray(preguntas) || preguntas.length !== 3) {
            return res.status(400).json({ error: "Debe proporcionar 3 preguntas de seguridad con respuestas." });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ error: "Las contraseñas no coinciden." });
        }
    
        const correoN = normalizeCorreo(correo);
        if (!isEmail(correoN)) return res.status(400).json({ error: "Correo inválido.", field: "correo" });
        if (!isCedula(cedula)) return res.status(400).json({ error: "Cédula inválida. Debe tener entre 7 y 9 dígitos.", field: "cedula" });
        if (!isTextOnly(primerNombre)) return res.status(400).json({ error: "El primer nombre solo debe contener letras.", field: "primerNombre" });
        if (!isNonEmpty(primerNombre)) return res.status(400).json({ error: "Primer nombre requerido.", field: "primerNombre" });
        if (segundoNombre && !isTextOnly(segundoNombre)) return res.status(400).json({ error: "El segundo nombre solo debe contener letras.", field: "segundoNombre" });
        if (!isTextOnly(primerApellido)) return res.status(400).json({ error: "El primer apellido solo debe contener letras.", field: "primerApellido" });
        if (!isNonEmpty(primerApellido)) return res.status(400).json({ error: "Primer apellido requerido.", field: "primerApellido" });
        if (segundoApellido && !isTextOnly(segundoApellido)) return res.status(400).json({ error: "El segundo apellido solo debe contener letras.", field: "segundoApellido" });
        if (String(password).length < 6) return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres.", field: "password" });
        if (!isPhone(telefono)) return res.status(400).json({ error: "Teléfono inválido. Debe tener exactamente 11 dígitos.", field: "telefono" });
        if (!isNonEmpty(direccion) || direccion.trim().length < 4) return res.status(400).json({ error: "Dirección requerida. Mínimo 4 caracteres.", field: "direccion" });
        if (!isNonEmpty(estado)) return res.status(400).json({ error: "Estado requerido.", field: "estado" });
        if (!isNonEmpty(municipio)) return res.status(400).json({ error: "Municipio requerido.", field: "municipio" });
        if (!['Natural', 'Juridica'].includes(tipoPersona)) return res.status(400).json({ error: "Tipo de persona inválido.", field: "tipoPersona" });
        if (!['Venezolano', 'Extranjero'].includes(nacionalidad)) return res.status(400).json({ error: "Nacionalidad inválida.", field: "nacionalidad" });

        const preguntaIds = preguntas.map(p => p.preguntaId);
        if (new Set(preguntaIds).size !== 3) {
            return res.status(400).json({ error: 'Debe seleccionar 3 preguntas distintas.' });
        }

        if (!preguntas.every(p => p.respuesta && p.respuesta.trim())) {
            return res.status(400).json({ error: 'Todas las preguntas deben tener respuesta.' });
        }

        const cedulaNum = parseCedula(cedula);
        if (!cedulaNum || cedulaNum < 1000000 || cedulaNum > 999999999) {
            return res.status(400).json({ error: "Cédula inválida. Debe tener entre 7 y 9 dígitos.", field: "cedula" });
        }

        let connection;
        try {
            connection = await db.getConnection();
            await connection.beginTransaction();
    
            const [existingCedula] = await connection.query("SELECT `Cedula` FROM `usuario` WHERE `Cedula` = ?", [cedulaNum]);
            if (existingCedula.length > 0) {
                await connection.rollback();
                return res.status(409).json({ error: "La cédula ingresada ya está registrada.", field: "cedula" });
            }

            const [existingCorreo] = await connection.query("SELECT `Correo` FROM `usuario` WHERE `Correo` = ?", [correoN]);
            if (existingCorreo.length > 0) {
                await connection.rollback();
                return res.status(409).json({ error: "Ya existe un usuario con este correo.", field: "correo" });
            }
    
            await connection.query(
                "INSERT INTO `usuario` (`Cedula`, `Correo`, `Tipo_Persona`, `Nacionalidad`, `Primer_Nombre`, `Segundo_Nombre`, `Primer_Apellido`, `Segundo_Apellido`, `Telefono`, `Direccion`, `Estado`, `Municipio`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [cedulaNum, correoN, tipoPersona, nacionalidad, primerNombre, segundoNombre || '', primerApellido, segundoApellido || '', telefono, direccion, estado, municipio]
            );
    
            await connection.query(
                "INSERT INTO `lista_clave` (`Usuario_Cedula`, `Clave`, `Status`) VALUES (?, ?, ?)",
                [cedulaNum, hashMD5(password), 1]
            );
    
            await connection.query(
                "INSERT INTO `rol_usuario` (`Rol_ID`, `Usuario_Cedula`, `Status`) VALUES (?, ?, ?)",
                [1, cedulaNum, 1]
            );

            for (const pregunta of preguntas) {
                const preguntaId = parseInt(pregunta.preguntaId, 10);
                if (isNaN(preguntaId) || preguntaId <= 0) {
                    await connection.rollback();
                    return res.status(400).json({ error: 'ID de pregunta inválido.' });
                }
                await connection.query(
                    "INSERT INTO `pregunta_usuario` (`Pregunta_ID`, `Usuario_Cedula`, `Respuesta`, `Posicion`, `Status`) VALUES (?, ?, ?, ?, ?)",
                    [preguntaId, cedulaNum, hashMD5(pregunta.respuesta), pregunta.posicion, 1]
                );
            }
    
            await connection.commit();
            return res.status(201).json({ success: true, cedula: cedulaNum });
    
        } catch (error) {
            if (connection) await connection.rollback();
            console.error("Error en el registro:", error);
            if (error.code === 'ER_DUP_ENTRY') {
                const msg = String(error.sqlMessage || '').toLowerCase();
                if (msg.includes('correo')) return res.status(409).json({ error: "Ya existe un usuario con este correo.", field: "correo" });
                if (msg.includes('cedula') || msg.includes('primary')) return res.status(409).json({ error: "La cédula ingresada ya está registrada.", field: "cedula" });
            }
            return res.status(500).json({ error: "Error interno del servidor al registrar el usuario." });
        } finally {
            if (connection) connection.release();
        }
    });

    app.post("/login", async (req, res) => {
        const { correo, password } = req.body || {};
        if (!correo || !password) {
            return res.status(400).json({ error: "Faltan datos" });
        }

        try {
            const correoN = normalizeCorreo(correo);
            const [rows] = await db.query(
                "SELECT u.Cedula as cedula, u.Correo as correo, lc.Clave as password FROM usuario u JOIN lista_clave lc ON u.Cedula = lc.Usuario_Cedula WHERE u.Correo = ? AND lc.Status = 1",
                [correoN]
            );
            
            const user = rows[0];
            if (!user || hashMD5(password) !== user.password) {
                return res.status(401).json({ error: "Credenciales inválidas" });
            }
            
            const token = jwt.sign({ cedula: user.cedula, correo: user.correo }, process.env.JWT_SECRET, { expiresIn: '1h' });
            
            res.cookie('access-token', token, {
                httpOnly: true,
                sameSite: 'Strict',
                maxAge: 3600000,
                secure: process.env.NODE_ENV === 'production'
            });

            res.json({ success: true, cedula: user.cedula });
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
            const correoN = normalizeCorreo(correo);
            const cedulaNum = parseCedula(cedula);
            if (!cedulaNum) {
                return res.status(400).json({ error: 'Cédula inválida', found: false });
            }
            const [rows] = await db.query(
                "SELECT u.Cedula as cedula FROM usuario u JOIN rol_usuario ru ON u.Cedula = ru.Usuario_Cedula WHERE u.Correo = ? AND u.Cedula = ? AND ru.Status = 1",
                [correoN, cedulaNum]
            );
            if (!rows.length) {
                return res.status(404).json({ error: 'Usuario no encontrado o inactivo', found: false });
            }
            
            const [preguntasRows] = await db.query(
                "SELECT p.ID as id, p.Pregunta as pregunta, pu.Posicion as posicion FROM pregunta_usuario pu JOIN pregunta p ON pu.Pregunta_ID = p.ID WHERE pu.Usuario_Cedula = ? AND pu.Status = 1 ORDER BY pu.Posicion",
                [cedulaNum]
            );
            
            if (!preguntasRows.length || preguntasRows.length < 3) {
                return res.status(404).json({ error: 'El usuario no tiene preguntas de seguridad configuradas', found: false });
            }
            
            return res.json({ 
                success: true, 
                found: true, 
                cedula: rows[0].cedula,
                questions: preguntasRows.map(p => ({ id: p.id, pregunta: p.pregunta, posicion: p.posicion }))
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

        const usuarioCedula = parseCedula(cedula);
        if (!usuarioCedula) {
            return res.status(400).json({ error: 'Cédula inválida.' });
        }

        try {
            const validation = await validateAnswers(usuarioCedula, respuestas);
            if (!validation.valid) {
                return res.status(validation.error.includes('coinciden') ? 401 : 404).json({ error: validation.error });
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

        const usuarioCedula = parseCedula(cedula);
        if (!usuarioCedula) {
            return res.status(400).json({ error: 'Cédula inválida.' });
        }

        let connection;
        try {
            connection = await db.getConnection();
            await connection.beginTransaction();

            const validation = await validateAnswers(usuarioCedula, respuestas);
            if (!validation.valid) {
                await connection.rollback();
                return res.status(validation.error.includes('coinciden') ? 401 : 404).json({ error: validation.error });
            }

            const [claveActual] = await connection.query(
                "SELECT `ID`, `Clave` FROM `lista_clave` WHERE `Usuario_Cedula` = ? AND `Status` = 1",
                [usuarioCedula]
            );

            if (!claveActual.length) {
                await connection.rollback();
                return res.status(404).json({ error: 'No se encontró una clave activa para el usuario.' });
            }

            await connection.query(
                "UPDATE `lista_clave` SET `Status` = 0 WHERE `Usuario_Cedula` = ? AND `Status` = 1",
                [usuarioCedula]
            );

            await connection.query(
                "INSERT INTO `historico_clave` (`Lista_ID`, `Clave`, `Status`) VALUES (?, ?, ?)",
                [claveActual[0].ID, claveActual[0].Clave, 0]
            );

            await connection.query(
                "INSERT INTO `lista_clave` (`Usuario_Cedula`, `Clave`, `Status`) VALUES (?, ?, ?)",
                [usuarioCedula, hashMD5(nuevaPassword), 1]
            );

            await connection.commit();
            return res.status(200).json({ success: true, message: 'Contraseña actualizada correctamente.' });

        } catch (error) {
            if (connection) await connection.rollback();
            console.error("Error en recover-password:", error);
            return res.status(500).json({ error: 'Error al recuperar la contraseña.' });
        } finally {
            if (connection) connection.release();
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
            const [rows] = await db.query("SELECT `ID` as id, `Pregunta` as pregunta FROM `pregunta` WHERE `Status` = 1 ORDER BY `ID`");
            if (!rows.length) {
                return res.status(404).json({ error: 'No hay preguntas de seguridad disponibles' });
            }
            return res.json({ preguntas: rows });
        } catch (e) {
            console.error("Error en /preguntas:", e);
            return res.status(500).json({ error: 'Error al obtener preguntas de seguridad' });
        }
    });


    app.get('/me', async (req, res) => {
        const u = verifyToken(req);
        if (!u) return res.status(403).json({ error: 'No autorizado' });
        try {
            const [rows] = await db.query(
                "SELECT u.Primer_Nombre as primerNombre, u.Segundo_Nombre as segundoNombre, u.Primer_Apellido as primerApellido, u.Segundo_Apellido as segundoApellido, u.Correo as correo FROM usuario u JOIN rol_usuario ru ON u.Cedula = ru.Usuario_Cedula WHERE u.Cedula = ? AND ru.Status = 1",
                [u.cedula]
            );
            const me = rows[0];
            if (!me) return res.status(404).json({ error: 'Usuario no encontrado o inactivo' });
            const nombre = `${me.primerNombre} ${me.segundoNombre || ''} ${me.primerApellido} ${me.segundoApellido || ''}`.trim();
            return res.json({ nombre, correo: me.correo });
        } catch (e) {
            console.error("Error en /me:", e);
            return res.status(500).json({ error: 'Error al obtener perfil' });
        }
    });

    app.get("/acceso", (req, res) => {
        const user = verifyToken(req);
        if (!user) return res.status(403).json({ error: "No autorizado" });
        res.set({
            'Cache-Control': 'no-store, no-cache, must-revalidate, private',
            'Pragma': 'no-cache',
            'Expires': '0'
        });
        res.sendFile(path.join(__dirname, "public", "acceso.html"));
    });

    app.post("/logout", (req, res) => {
        res.clearCookie('access-token');
        res.json({ success: true });
    });
}
