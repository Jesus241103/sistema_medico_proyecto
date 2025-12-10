const db = require("../connex.js");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const path = require("path");

const normalizarCorreo = (correo) => String(correo || "").trim().toLowerCase();
const esCorreoValido = (valor) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(valor || ""));
const calcularHashMD5 = (texto) => crypto.createHash("md5").update(texto, "utf8").digest("hex");
const convertirCedulaNumero = (cedula) => {
    const numero = parseInt(String(cedula).trim(), 10);
    return isNaN(numero) || numero <= 0 ? null : numero;
};

const validarRespuestas = async (cedula, respuestas) => {
    const [filasPreguntas] = await db.query(
        "SELECT `Respuesta` FROM `pregunta_administrador` WHERE `administrador_Cedula` = ? AND `Status` = 1 ORDER BY `ID`",
        [cedula]
    );
    if (!filasPreguntas.length || filasPreguntas.length < 3) {
        return { valido: false, error: "El usuario no tiene preguntas de seguridad configuradas." };
    }
    for (let i = 0; i < 3; i++) {
        if (calcularHashMD5(respuestas[i]) !== filasPreguntas[i].Respuesta) {
            return { valido: false, error: `Las respuestas no coinciden en la pregunta ${i + 1}.` };
        }
    }
    return { valido: true };
};

const verificarTokenAdmin = (req) => {
    try {
        return jwt.verify(req.cookies["admin-token"], process.env.JWT_SECRET);
    } catch {
        return null;
    }
};

module.exports = (app) => {
    app.post("/admin/login", async (req, res) => {
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
            const [filas] = await db.query(
                "SELECT a.Cedula AS cedula, a.Correo AS correo, lc.Clave AS clave FROM administrador a JOIN lista_clave_administrador lc ON a.Cedula = lc.medico_Cedula WHERE a.Correo = ? AND lc.Status = 1 AND a.Status = 1",
                [correoNormalizado]
            );

            const usuario = filas[0];
            if (!usuario || calcularHashMD5(password) !== usuario.clave) {
                return res.status(401).json({ error: "Credenciales inválidas" });
            }

            const token = jwt.sign(
                { cedula: usuario.cedula, correo: usuario.correo, rol: "Admin" },
                process.env.JWT_SECRET,
                { expiresIn: "1h" }
            );

            res.cookie("admin-token", token, {
                httpOnly: true,
                sameSite: "Strict",
                maxAge: 3600000,
                secure: process.env.NODE_ENV === "production"
            });

            return res.json({ success: true, cedula: usuario.cedula });
        } catch (error) {
            console.error("Error en /admin/login:", error);
            return res.status(500).json({ error: "Error al autenticar" });
        }
    });

    app.get("/admin/me", async (req, res) => {
        const usuarioSesion = verificarTokenAdmin(req);
        if (!usuarioSesion) return res.status(403).json({ error: "No autorizado" });
        try {
            const [filas] = await db.query(
                "SELECT Primer_Nombre AS primerNombre, Segundo_Nombre AS segundoNombre, Primer_Apellido AS primerApellido, Segundo_Apellido AS segundoApellido, Correo AS correo FROM administrador WHERE Cedula = ? AND Status = 1",
                [usuarioSesion.cedula]
            );
            const perfil = filas[0];
            if (!perfil) return res.status(404).json({ error: "Usuario no encontrado o inactivo" });
            const nombre = `${perfil.primerNombre} ${perfil.segundoNombre || ""} ${perfil.primerApellido} ${perfil.segundoApellido || ""}`.trim();
            return res.json({ nombre, correo: perfil.correo });
        } catch (error) {
            console.error("Error en /admin/me:", error);
            return res.status(500).json({ error: "Error al obtener perfil" });
        }
    });

    app.get("/admin/acceso", (req, res) => {
        const usuarioSesion = verificarTokenAdmin(req);
        if (!usuarioSesion) return res.status(403).json({ error: "No autorizado" });
        res.set({
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
            Expires: "0"
        });
        res.sendFile(path.join(__dirname, "..", "public", "acceso-admin.html"));
    });

    app.post("/admin/logout", (req, res) => {
        res.clearCookie("admin-token");
        res.json({ success: true });
    });

    app.post("/admin/recover-lookup", async (req, res) => {
        const { correo, cedula } = req.body || {};
        if (!correo || !cedula) {
            return res.status(400).json({ error: "Faltan datos", found: false });
        }
        const correoNormalizado = normalizarCorreo(correo);
        const cedulaNum = convertirCedulaNumero(cedula);
        if (!esCorreoValido(correoNormalizado) || !cedulaNum) {
            return res.status(400).json({ error: "Datos inválidos", found: false });
        }
        try {
            const [filas] = await db.query(
                "SELECT Cedula FROM administrador WHERE Correo = ? AND Cedula = ? AND Status = 1",
                [correoNormalizado, cedulaNum]
            );
            if (!filas.length) {
                return res.status(404).json({ error: "Usuario no encontrado o inactivo", found: false });
            }
            const [preguntasRows] = await db.query(
                "SELECT ID as id, Pregunta as pregunta FROM pregunta_administrador WHERE administrador_Cedula = ? AND Status = 1 ORDER BY ID",
                [cedulaNum]
            );
            if (!preguntasRows.length || preguntasRows.length < 3) {
                return res.status(404).json({ error: "El usuario no tiene preguntas de seguridad configuradas", found: false });
            }
            return res.json({
                success: true,
                found: true,
                cedula: cedulaNum,
                questions: preguntasRows.map((p, idx) => ({ id: p.id, pregunta: p.pregunta, posicion: idx + 1 }))
            });
        } catch (error) {
            console.error("Error en /admin/recover-lookup:", error);
            return res.status(500).json({ error: "Error al buscar usuario", found: false });
        }
    });

    app.post("/admin/verify-answers", async (req, res) => {
        const { cedula, respuestas } = req.body || {};
        if (!cedula || !respuestas || !Array.isArray(respuestas) || respuestas.length !== 3) {
            return res.status(400).json({ error: "Faltan datos requeridos." });
        }
        const cedulaNum = convertirCedulaNumero(cedula);
        if (!cedulaNum) {
            return res.status(400).json({ error: "Cédula inválida." });
        }
        try {
            const resultado = await validarRespuestas(cedulaNum, respuestas);
            if (!resultado.valido) {
                return res.status(resultado.error.includes("coinciden") ? 401 : 404).json({ error: resultado.error });
            }
            return res.json({ success: true, message: "Respuestas correctas." });
        } catch (error) {
            console.error("Error en /admin/verify-answers:", error);
            return res.status(500).json({ error: "Error al verificar las respuestas." });
        }
    });

    app.post("/admin/recover-password", async (req, res) => {
        const { cedula, respuestas, nuevaPassword, confirmPassword } = req.body || {};
        if (!cedula || !respuestas || !Array.isArray(respuestas) || respuestas.length !== 3 || !nuevaPassword || !confirmPassword) {
            return res.status(400).json({ error: "Faltan datos requeridos." });
        }
        if (nuevaPassword !== confirmPassword) {
            return res.status(400).json({ error: "Las contraseñas no coinciden." });
        }
        if (String(nuevaPassword).length < 6) {
            return res.status(400).json({ error: "La contraseña debe tener al menos 6 caracteres." });
        }
        const cedulaNum = convertirCedulaNumero(cedula);
        if (!cedulaNum) {
            return res.status(400).json({ error: "Cédula inválida." });
        }
        const nuevaHash = calcularHashMD5(nuevaPassword);

        let conexion;
        try {
            conexion = await db.getConnection();
            await conexion.beginTransaction();

            const resultado = await validarRespuestas(cedulaNum, respuestas);
            if (!resultado.valido) {
                await conexion.rollback();
                return res.status(resultado.error.includes("coinciden") ? 401 : 404).json({ error: resultado.error });
            }

            const [claveActual] = await conexion.query(
                "SELECT `ID`, `Clave` FROM `lista_clave_administrador` WHERE `medico_Cedula` = ? AND `Status` = 1",
                [cedulaNum]
            );
            if (!claveActual.length) {
                await conexion.rollback();
                return res.status(404).json({ error: "No se encontró una clave activa para el usuario." });
            }

            const [clavesPrevias] = await conexion.query(
                "SELECT 1 FROM `lista_clave_administrador` WHERE `medico_Cedula` = ? AND `Clave` = ? UNION SELECT 1 FROM `historico_clave_administrador` h JOIN `lista_clave_administrador` l ON h.`lista_clave_administrador_ID` = l.`ID` WHERE l.`medico_Cedula` = ? AND h.`Clave` = ? LIMIT 1",
                [cedulaNum, nuevaHash, cedulaNum, nuevaHash]
            );
            if (clavesPrevias.length > 0) {
                await conexion.rollback();
                return res.status(400).json({ error: "La nueva contraseña no puede ser igual a alguna anterior." });
            }

            await conexion.query(
                "UPDATE `lista_clave_administrador` SET `Status` = 0 WHERE `medico_Cedula` = ? AND `Status` = 1",
                [cedulaNum]
            );

            await conexion.query(
                "INSERT INTO `historico_clave_administrador` (`Clave`, `Status`, `lista_clave_administrador_ID`) VALUES (?, ?, ?)",
                [claveActual[0].Clave, 0, claveActual[0].ID]
            );

            await conexion.query(
                "INSERT INTO `lista_clave_administrador` (`medico_Cedula`, `Clave`, `Status`) VALUES (?, ?, ?)",
                [cedulaNum, nuevaHash, 1]
            );

            await conexion.commit();
            return res.json({ success: true, message: "Contraseña actualizada correctamente." });
        } catch (error) {
            if (conexion) await conexion.rollback();
            console.error("Error en /admin/recover-password:", error);
            return res.status(500).json({ error: "Error al recuperar la contraseña." });
        } finally {
            if (conexion) conexion.release();
        }
    });
};
