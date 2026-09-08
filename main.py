import os
import requests
import psycopg2
from dotenv import load_dotenv
from fastapi import Depends, FastAPI

# Cargar la conexión de PostgreSQL desde pass.env
load_dotenv("pass.env", override=True)

PG_CONNECTION_STRING = os.getenv("PG_CONNECTION_STRING")
HAPI_FHIR_URL = os.getenv("HAPI_FHIR_URL")

if not HAPI_FHIR_URL:
    raise ValueError(
        "No se encontró HAPI_FHIR_URL en pass.env"
    )

if not PG_CONNECTION_STRING:
    raise ValueError(
        "No se encontró PG_CONNECTION_STRING en el archivo pass.env"
    )


app = FastAPI(
    title="API de Triaje Hospitalario",
    description=(
        "API para apoyar el registro y seguimiento del proceso de "
        "triaje del Hospital San Andrés de Tumaco."
    ),
    version="1.0.0",
)


def get_db():
    """
    Abre una conexión con PostgreSQL para cada petición
    y la cierra cuando la petición termina.
    """
    conexion = psycopg2.connect(PG_CONNECTION_STRING)

    try:
        yield conexion
    finally:
        conexion.close()


@app.get("/", tags=["Sistema"])
def inicio():
    return {
        "mensaje": "API del sistema de triaje funcionando"
    }


@app.get("/estado-bd", tags=["Sistema"])
def verificar_base_datos(db=Depends(get_db)):
    cursor = db.cursor()

    try:
        cursor.execute(
            "SELECT current_database(), current_user;"
        )
        nombre_bd, usuario_bd = cursor.fetchone()

        return {
            "estado": "conectada",
            "base_datos": nombre_bd,
            "usuario": usuario_bd,
        }
    finally:
        cursor.close()
# Ejecutar una sola vez después de crear main.py

from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
import psycopg2.extras
from fastapi import HTTPException, status
from fastapi.security import (
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
)
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel


JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 60

if not JWT_SECRET_KEY:
    raise ValueError(
        "No se encontró JWT_SECRET_KEY en pass.env"
    )


password_hasher = PasswordHash.recommended()

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="auth/login"
)


class Token(BaseModel):
    access_token: str
    token_type: str


def crear_token(
    numero_documento: int,
    rol: str,
):
    fecha_expiracion = (
        datetime.now(timezone.utc)
        + timedelta(
            minutes=JWT_EXPIRATION_MINUTES
        )
    )

    datos_token = {
        "sub": str(numero_documento),
        "rol": rol,
        "exp": fecha_expiracion,
    }

    return jwt.encode(
        datos_token,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


@app.post(
    "/auth/login",
    response_model=Token,
    tags=["Autenticación"],
)
def iniciar_sesion(
    formulario: Annotated[
        OAuth2PasswordRequestForm,
        Depends(),
    ],
    db=Depends(get_db),
):
    cursor = db.cursor(
        cursor_factory=(
            psycopg2.extras.RealDictCursor
        )
    )

    try:
        cursor.execute(
            """
            SELECT
                u.numero_documento_usuario,
                u.username,
                u.password_hash,
                r.nombre AS rol
            FROM usuarios AS u
            INNER JOIN roles AS r
                ON r.id_rol = u.id_rol
            WHERE u.username = %s
              AND u.estado = TRUE
              AND u.is_deleted = FALSE
              AND r.is_active = TRUE;
            """,
            (formulario.username,),
        )

        usuario = cursor.fetchone()

    finally:
        cursor.close()

    credenciales_invalidas = (
        usuario is None
        or not password_hasher.verify(
            formulario.password,
            usuario["password_hash"],
        )
    )

    if credenciales_invalidas:
        raise HTTPException(
            status_code=(
                status.HTTP_401_UNAUTHORIZED
            ),
            detail=(
                "Usuario o contraseña incorrectos"
            ),
            headers={
                "WWW-Authenticate": "Bearer"
            },
        )

    token = crear_token(
        usuario[
            "numero_documento_usuario"
        ],
        usuario["rol"],
    )

    return {
        "access_token": token,
        "token_type": "bearer",
    }


def obtener_usuario_actual(
    token: Annotated[
        str,
        Depends(oauth2_scheme),
    ],
    db=Depends(get_db),
):
    excepcion_credenciales = HTTPException(
        status_code=(
            status.HTTP_401_UNAUTHORIZED
        ),
        detail=(
            "No fue posible validar el token"
        ),
        headers={
            "WWW-Authenticate": "Bearer"
        },
    )

    try:
        contenido = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
        )

        numero_documento = contenido.get(
            "sub"
        )

        if numero_documento is None:
            raise excepcion_credenciales

        numero_documento = int(
            numero_documento
        )

    except (InvalidTokenError, ValueError):
        raise excepcion_credenciales

    cursor = db.cursor(
        cursor_factory=(
            psycopg2.extras.RealDictCursor
        )
    )

    try:
        cursor.execute(
            """
            SELECT
                u.numero_documento_usuario,
                u.username,
                u.nombres,
                u.apellidos,
                u.email,
                r.nombre AS rol
            FROM usuarios AS u
            INNER JOIN roles AS r
                ON r.id_rol = u.id_rol
            WHERE u.numero_documento_usuario = %s
              AND u.estado = TRUE
              AND u.is_deleted = FALSE
              AND r.is_active = TRUE;
            """,
            (numero_documento,),
        )

        usuario = cursor.fetchone()

    finally:
        cursor.close()

    if usuario is None:
        raise excepcion_credenciales

    return usuario


@app.get(
    "/auth/me",
    tags=["Autenticación"],
)
def consultar_mi_usuario(
    usuario_actual=Depends(
        obtener_usuario_actual
    ),
):
    return usuario_actual


# BLOQUE_PERMISOS_ROLES_V1
# CONTROL DE ACCESO SEGÚN EL ROL

def requerir_roles(*roles_permitidos):
    """
    Permite utilizar un endpoint solamente
    a los roles indicados.
    """

    def verificar_rol(
        usuario_actual=Depends(
            obtener_usuario_actual
        ),
    ):
        rol_actual = usuario_actual["rol"]

        if rol_actual not in roles_permitidos:
            raise HTTPException(
                status_code=(
                    status.HTTP_403_FORBIDDEN
                ),
                detail=(
                    "El rol del usuario no tiene "
                    "permiso para realizar esta operación"
                ),
            )

        return usuario_actual

    return verificar_rol


# BLOQUE_USUARIOS_V1
# MODELOS Y ENDPOINTS DE USUARIOS

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class UsuarioCreate(BaseModel):
    numero_documento_usuario: int = Field(gt=0)

    username: str = Field(
        min_length=3,
        max_length=50,
    )

    password: str = Field(
        min_length=8,
        max_length=100,
    )

    nombres: str = Field(
        min_length=1,
        max_length=100,
    )

    apellidos: str = Field(
        min_length=1,
        max_length=100,
    )

    email: str | None = Field(
        default=None,
        max_length=150,
    )

    telefono: str | None = Field(
        default=None,
        max_length=20,
    )

    rol: Literal[
        "Admin",
        "Medico",
        "Administrativo",
        "Paciente",
    ]


class UsuarioOut(BaseModel):
    numero_documento_usuario: int
    username: str
    nombres: str
    apellidos: str
    email: str | None
    telefono: str | None
    rol: str
    estado: bool
    is_deleted: bool
    created_at: datetime


@app.post(
    "/usuarios",
    response_model=UsuarioOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Usuarios"],
)
def crear_usuario(
    datos: UsuarioCreate,
    db=Depends(get_db),
    usuario_admin=Depends(
        requerir_roles("Admin")
    ),
):
    """
    Crea un usuario y cifra su contraseña.
    Disponible únicamente para Admin.
    """
    cursor = db.cursor(
        cursor_factory=(
            psycopg2.extras.RealDictCursor
        )
    )

    try:
        cursor.execute(
            """
            SELECT id_rol
            FROM roles
            WHERE nombre = %s
              AND is_active = TRUE;
            """,
            (datos.rol,),
        )

        rol_encontrado = cursor.fetchone()

        if rol_encontrado is None:
            raise HTTPException(
                status_code=(
                    status.HTTP_400_BAD_REQUEST
                ),
                detail=(
                    "El rol indicado no existe "
                    "o se encuentra inactivo"
                ),
            )

        password_hash_nuevo = (
            password_hasher.hash(
                datos.password
            )
        )

        cursor.execute(
            """
            INSERT INTO usuarios (
                numero_documento_usuario,
                id_rol,
                username,
                password_hash,
                nombres,
                apellidos,
                email,
                telefono
            )
            VALUES (
                %s, %s, %s, %s,
                %s, %s, %s, %s
            )
            RETURNING
                numero_documento_usuario,
                username,
                nombres,
                apellidos,
                email,
                telefono,
                estado,
                is_deleted,
                created_at;
            """,
            (
                datos.numero_documento_usuario,
                rol_encontrado["id_rol"],
                datos.username.strip(),
                password_hash_nuevo,
                datos.nombres.strip(),
                datos.apellidos.strip(),
                datos.email,
                datos.telefono,
            ),
        )

        usuario_creado = cursor.fetchone()
        usuario_creado["rol"] = datos.rol

        db.commit()

        return usuario_creado

    except psycopg2.errors.UniqueViolation:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Ya existe un usuario con ese "
                "documento o nombre de usuario"
            ),
        )

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.get(
    "/usuarios",
    response_model=list[UsuarioOut],
    tags=["Usuarios"],
)
def listar_usuarios(
    incluir_eliminados: bool = False,
    db=Depends(get_db),
    usuario_admin=Depends(
        requerir_roles("Admin")
    ),
):
    """
    Lista usuarios. Admin puede decidir si incluye
    los registros eliminados lógicamente.
    """
    cursor = db.cursor(
        cursor_factory=(
            psycopg2.extras.RealDictCursor
        )
    )

    try:
        cursor.execute(
            """
            SELECT
                u.numero_documento_usuario,
                u.username,
                u.nombres,
                u.apellidos,
                u.email,
                u.telefono,
                r.nombre AS rol,
                u.estado,
                u.is_deleted,
                u.created_at
            FROM usuarios AS u
            INNER JOIN roles AS r
                ON r.id_rol = u.id_rol
            WHERE (
                %s = TRUE
                OR u.is_deleted = FALSE
            )
            ORDER BY
                u.created_at,
                u.numero_documento_usuario;
            """,
            (incluir_eliminados,),
        )

        return cursor.fetchall()

    finally:
        cursor.close()


@app.get(
    "/usuarios/{numero_documento}",
    response_model=UsuarioOut,
    tags=["Usuarios"],
)
def consultar_usuario(
    numero_documento: int,
    db=Depends(get_db),
    usuario_admin=Depends(
        requerir_roles("Admin")
    ),
):
    """
    Consulta un usuario por número de documento.
    Disponible únicamente para Admin.
    """
    cursor = db.cursor(
        cursor_factory=(
            psycopg2.extras.RealDictCursor
        )
    )

    try:
        cursor.execute(
            """
            SELECT
                u.numero_documento_usuario,
                u.username,
                u.nombres,
                u.apellidos,
                u.email,
                u.telefono,
                r.nombre AS rol,
                u.estado,
                u.is_deleted,
                u.created_at
            FROM usuarios AS u
            INNER JOIN roles AS r
                ON r.id_rol = u.id_rol
            WHERE u.numero_documento_usuario = %s;
            """,
            (numero_documento,),
        )

        usuario = cursor.fetchone()

    finally:
        cursor.close()

    if usuario is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado",
        )

    return usuario


# BLOQUE_GESTION_USUARIOS_V1
# EDICIÓN, ELIMINACIÓN LÓGICA, RESTAURACIÓN Y AUDITORÍA


import json
from typing import Literal

from psycopg2.errors import UniqueViolation
from psycopg2.extras import Json, RealDictCursor
from pydantic import BaseModel, Field


class UsuarioUpdate(BaseModel):
    username: str | None = Field(
        default=None,
        min_length=3,
        max_length=50,
    )
    nombres: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )
    apellidos: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )
    email: str | None = None
    telefono: str | None = None
    estado: bool | None = None
    rol: Literal[
        "Admin",
        "Medico",
        "Administrativo",
        "Paciente",
    ] | None = None


def convertir_json(datos):
    """
    Permite guardar fechas y otros tipos de PostgreSQL
    dentro de las columnas JSONB de auditoría.
    """
    return Json(
        datos,
        dumps=lambda valor: json.dumps(
            valor,
            default=str,
            ensure_ascii=False,
        ),
    )


def obtener_usuario_para_auditoria(
    cursor,
    numero_documento,
):
    cursor.execute(
        """
        SELECT
            u.numero_documento_usuario,
            u.id_rol,
            r.nombre AS rol,
            u.username,
            u.nombres,
            u.apellidos,
            u.email,
            u.telefono,
            u.estado,
            u.is_deleted,
            u.created_at,
            u.updated_at,
            u.deleted_at,
            u.deleted_by
        FROM usuarios AS u
        INNER JOIN roles AS r
            ON r.id_rol = u.id_rol
        WHERE u.numero_documento_usuario = %s;
        """,
        (numero_documento,),
    )

    usuario = cursor.fetchone()

    if usuario is None:
        return None

    return dict(usuario)


def registrar_auditoria(
    cursor,
    tabla_afectada,
    registro_id,
    accion,
    realizado_por,
    datos_anteriores=None,
    datos_nuevos=None,
):
    cursor.execute(
        """
        INSERT INTO auditoria_cambios (
            tabla_afectada,
            registro_id,
            accion,
            datos_anteriores,
            datos_nuevos,
            realizado_por
        )
        VALUES (%s, %s, %s, %s, %s, %s);
        """,
        (
            tabla_afectada,
            str(registro_id),
            accion,
            convertir_json(datos_anteriores),
            convertir_json(datos_nuevos),
            realizado_por,
        ),
    )


@app.put(
    "/usuarios/{numero_documento}",
    response_model=UsuarioOut,
    tags=["Usuarios"],
)
def editar_usuario(
    numero_documento: int,
    cambios: UsuarioUpdate,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_usuario_para_auditoria(
                cursor,
                numero_documento,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )

        if datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "No se puede editar un usuario eliminado"
                ),
            )

        datos_actualizacion = cambios.model_dump(
            exclude_unset=True
        )

        if not datos_actualizacion:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No se enviaron datos para actualizar",
            )

        nuevo_rol = datos_actualizacion.pop(
            "rol",
            None,
        )

        if nuevo_rol is not None:
            cursor.execute(
                """
                SELECT id_rol
                FROM roles
                WHERE nombre = %s
                  AND is_active = TRUE;
                """,
                (nuevo_rol,),
            )

            resultado_rol = cursor.fetchone()

            if resultado_rol is None:
                raise HTTPException(
                    status_code=(
                        status.HTTP_400_BAD_REQUEST
                    ),
                    detail="El rol indicado no está activo",
                )

            datos_actualizacion["id_rol"] = (
                resultado_rol["id_rol"]
            )

        columnas_permitidas = {
            "username",
            "nombres",
            "apellidos",
            "email",
            "telefono",
            "estado",
            "id_rol",
        }

        asignaciones = []
        valores = []

        for columna, valor in datos_actualizacion.items():
            if columna not in columnas_permitidas:
                continue

            asignaciones.append(
                f"{columna} = %s"
            )
            valores.append(valor)

        if not asignaciones:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No hay campos válidos para actualizar",
            )

        asignaciones.append("updated_at = NOW()")
        valores.append(numero_documento)

        cursor.execute(
            f"""
            UPDATE usuarios
            SET {", ".join(asignaciones)}
            WHERE numero_documento_usuario = %s;
            """,
            valores,
        )

        datos_nuevos = obtener_usuario_para_auditoria(
            cursor,
            numero_documento,
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="usuarios",
            registro_id=numero_documento,
            accion="EDITAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except UniqueViolation:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "El nombre de usuario o el correo "
                "ya se encuentran registrados"
            ),
        )

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.delete(
    "/usuarios/{numero_documento}",
    response_model=UsuarioOut,
    tags=["Usuarios"],
)
def eliminar_usuario(
    numero_documento: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    if (
        numero_documento
        == usuario_actual["numero_documento_usuario"]
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "El administrador no puede "
                "eliminar su propio usuario"
            ),
        )

    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_usuario_para_auditoria(
                cursor,
                numero_documento,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )

        if datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El usuario ya está eliminado",
            )

        cursor.execute(
            """
            UPDATE usuarios
            SET
                is_deleted = TRUE,
                estado = FALSE,
                deleted_at = NOW(),
                deleted_by = %s,
                updated_at = NOW()
            WHERE numero_documento_usuario = %s;
            """,
            (
                usuario_actual[
                    "numero_documento_usuario"
                ],
                numero_documento,
            ),
        )

        datos_nuevos = obtener_usuario_para_auditoria(
            cursor,
            numero_documento,
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="usuarios",
            registro_id=numero_documento,
            accion="ELIMINAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.patch(
    "/usuarios/{numero_documento}/restaurar",
    response_model=UsuarioOut,
    tags=["Usuarios"],
)
def restaurar_usuario(
    numero_documento: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_usuario_para_auditoria(
                cursor,
                numero_documento,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado",
            )

        if not datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El usuario no está eliminado",
            )

        cursor.execute(
            """
            UPDATE usuarios
            SET
                is_deleted = FALSE,
                estado = TRUE,
                deleted_at = NULL,
                deleted_by = NULL,
                updated_at = NOW()
            WHERE numero_documento_usuario = %s;
            """,
            (numero_documento,),
        )

        datos_nuevos = obtener_usuario_para_auditoria(
            cursor,
            numero_documento,
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="usuarios",
            registro_id=numero_documento,
            accion="RESTAURAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


# BLOQUE_PACIENTES_V2
# ENDPOINTS BÁSICOS DE PACIENTES

from datetime import date, datetime
from typing import Literal

from psycopg2.errors import UniqueViolation
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field


class PacienteCreate(BaseModel):
    numero_documento_paciente: int = Field(gt=0)

    tipo_documento: str = Field(
        min_length=1,
        max_length=20,
    )

    nombres: str = Field(
        min_length=1,
        max_length=100,
    )

    apellidos: str = Field(
        min_length=1,
        max_length=100,
    )

    fecha_nacimiento: date | None = None

    sexo: str | None = Field(
        default=None,
        max_length=20,
    )

    telefono: str | None = Field(
        default=None,
        max_length=20,
    )

    direccion: str | None = Field(
        default=None,
        max_length=200,
    )

    municipio_residencia: str | None = Field(
        default=None,
        max_length=100,
    )

    zona_residencia: Literal[
        "urbana",
        "rural_dispersa",
    ] | None = None


class PacienteOut(BaseModel):
    numero_documento_paciente: int
    tipo_documento: str
    nombres: str
    apellidos: str
    fecha_nacimiento: date | None
    sexo: str | None
    telefono: str | None
    direccion: str | None
    municipio_residencia: str | None
    zona_residencia: str | None
    created_at: datetime | None
    updated_at: datetime | None
    is_deleted: bool


@app.post(
    "/pacientes",
    response_model=PacienteOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Pacientes"],
)
def crear_paciente(
    paciente: PacienteCreate,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        # Buscar una cuenta con el mismo documento.
        # La relación se realiza automáticamente.
        cursor.execute(
            """
            SELECT
                u.numero_documento_usuario,
                u.estado,
                u.is_deleted,
                r.nombre AS rol,
                r.is_active AS rol_activo
            FROM usuarios AS u
            INNER JOIN roles AS r
                ON r.id_rol = u.id_rol
            WHERE u.numero_documento_usuario = %s;
            """,
            (
                paciente.numero_documento_paciente,
            ),
        )

        usuario_coincidente = cursor.fetchone()
        id_usuario_asociado = None

        if usuario_coincidente is not None:
            if usuario_coincidente["rol"] != "Paciente":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "Ya existe un usuario con ese "
                        "documento, pero no tiene rol Paciente"
                    ),
                )

            cuenta_activa = (
                usuario_coincidente["estado"]
                and not usuario_coincidente["is_deleted"]
                and usuario_coincidente["rol_activo"]
            )

            if not cuenta_activa:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "La cuenta del paciente está "
                        "inactiva o eliminada"
                    ),
                )

            id_usuario_asociado = (
                usuario_coincidente[
                    "numero_documento_usuario"
                ]
            )

        cursor.execute(
            """
            INSERT INTO pacientes (
                numero_documento_paciente,
                id_usuario,
                tipo_documento,
                nombres,
                apellidos,
                fecha_nacimiento,
                sexo,
                telefono,
                direccion,
                municipio_residencia,
                zona_residencia
            )
            VALUES (
                %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s
            )
            RETURNING
                numero_documento_paciente,
                tipo_documento,
                nombres,
                apellidos,
                fecha_nacimiento,
                sexo,
                telefono,
                direccion,
                municipio_residencia,
                zona_residencia,
                created_at,
                updated_at,
                is_deleted;
            """,
            (
                paciente.numero_documento_paciente,
                id_usuario_asociado,
                paciente.tipo_documento,
                paciente.nombres,
                paciente.apellidos,
                paciente.fecha_nacimiento,
                paciente.sexo,
                paciente.telefono,
                paciente.direccion,
                paciente.municipio_residencia,
                paciente.zona_residencia,
            ),
        )

        paciente_creado = dict(
            cursor.fetchone()
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="pacientes",
            registro_id=(
                paciente.numero_documento_paciente
            ),
            accion="CREAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=None,
            datos_nuevos=paciente_creado,
        )

        db.commit()
        return paciente_creado

    except UniqueViolation:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Ya existe un paciente con ese "
                "número de documento"
            ),
        )

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.get(
    "/pacientes",
    response_model=list[PacienteOut],
    tags=["Pacientes"],
)
def listar_pacientes(
    incluir_eliminados: bool = False,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin", "Medico")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT
                numero_documento_paciente,
                tipo_documento,
                nombres,
                apellidos,
                fecha_nacimiento,
                sexo,
                telefono,
                direccion,
                municipio_residencia,
                zona_residencia,
                created_at,
                updated_at,
                is_deleted
            FROM pacientes
            WHERE (
                %s = TRUE
                OR is_deleted = FALSE
            )
            ORDER BY apellidos, nombres;
            """,
            (incluir_eliminados,),
        )

        pacientes = cursor.fetchall()
        return pacientes

    finally:
        cursor.close()


@app.get(
    "/pacientes/{numero_documento}",
    response_model=PacienteOut,
    tags=["Pacientes"],
)
def consultar_paciente(
    numero_documento: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        obtener_usuario_actual
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT
                numero_documento_paciente,
                tipo_documento,
                nombres,
                apellidos,
                fecha_nacimiento,
                sexo,
                telefono,
                direccion,
                municipio_residencia,
                zona_residencia,
                created_at,
                updated_at,
                is_deleted
            FROM pacientes
            WHERE numero_documento_paciente = %s;
            """,
            (numero_documento,),
        )

        paciente = cursor.fetchone()

    finally:
        cursor.close()

    if paciente is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Paciente no encontrado",
        )

    rol_actual = usuario_actual["rol"]

    if rol_actual == "Administrativo":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "El personal administrativo no puede "
                "consultar información clínica"
            ),
        )

    if rol_actual == "Paciente":
        if (
            numero_documento
            != usuario_actual[
                "numero_documento_usuario"
            ]
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "El paciente solamente puede "
                    "consultar su propia información"
                ),
            )

    elif rol_actual not in {
        "Admin",
        "Medico",
    }:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "No tiene permiso para "
                "consultar pacientes"
            ),
        )

    if (
        paciente["is_deleted"]
        and rol_actual != "Admin"
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Paciente no encontrado",
        )

    return paciente


# BLOQUE_GESTION_PACIENTES_V1
# SOFT EDIT, SOFT DELETE Y RESTAURACIÓN DE PACIENTES

from datetime import date
from typing import Literal

from psycopg2.errors import UniqueViolation
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field


class PacienteUpdate(BaseModel):
    tipo_documento: str | None = Field(
        default=None,
        min_length=1,
        max_length=20,
    )

    nombres: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    apellidos: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    fecha_nacimiento: date | None = None

    sexo: str | None = Field(
        default=None,
        max_length=20,
    )

    telefono: str | None = Field(
        default=None,
        max_length=20,
    )

    direccion: str | None = Field(
        default=None,
        max_length=200,
    )

    municipio_residencia: str | None = Field(
        default=None,
        max_length=100,
    )

    zona_residencia: Literal[
        "urbana",
        "rural_dispersa",
    ] | None = None


def obtener_paciente_para_auditoria(
    cursor,
    numero_documento,
):
    cursor.execute(
        """
        SELECT
            numero_documento_paciente,
            id_usuario,
            tipo_documento,
            nombres,
            apellidos,
            fecha_nacimiento,
            sexo,
            telefono,
            direccion,
            municipio_residencia,
            zona_residencia,
            created_at,
            updated_at,
            is_deleted,
            deleted_at,
            deleted_by
        FROM pacientes
        WHERE numero_documento_paciente = %s;
        """,
        (numero_documento,),
    )

    paciente = cursor.fetchone()

    if paciente is None:
        return None

    return dict(paciente)


@app.put(
    "/pacientes/{numero_documento}",
    response_model=PacienteOut,
    tags=["Pacientes"],
)
def editar_paciente(
    numero_documento: int,
    cambios: PacienteUpdate,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_paciente_para_auditoria(
                cursor,
                numero_documento,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Paciente no encontrado",
            )

        if datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "No se puede editar un paciente "
                    "eliminado"
                ),
            )

        datos_actualizacion = cambios.model_dump(
            exclude_unset=True
        )

        if not datos_actualizacion:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "No se enviaron datos para actualizar"
                ),
            )

        campos_obligatorios = {
            "tipo_documento",
            "nombres",
            "apellidos",
        }

        for campo in campos_obligatorios:
            if (
                campo in datos_actualizacion
                and datos_actualizacion[campo] is None
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"El campo {campo} no puede ser nulo"
                    ),
                )

        columnas_permitidas = {
            "tipo_documento",
            "nombres",
            "apellidos",
            "fecha_nacimiento",
            "sexo",
            "telefono",
            "direccion",
            "municipio_residencia",
            "zona_residencia",
        }

        asignaciones = []
        valores = []

        for columna, valor in datos_actualizacion.items():
            if columna not in columnas_permitidas:
                continue

            asignaciones.append(
                f"{columna} = %s"
            )
            valores.append(valor)

        if not asignaciones:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "No hay campos válidos para actualizar"
                ),
            )

        asignaciones.append("updated_at = NOW()")
        valores.append(numero_documento)

        cursor.execute(
            f"""
            UPDATE pacientes
            SET {", ".join(asignaciones)}
            WHERE numero_documento_paciente = %s;
            """,
            valores,
        )

        datos_nuevos = (
            obtener_paciente_para_auditoria(
                cursor,
                numero_documento,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="pacientes",
            registro_id=numero_documento,
            accion="EDITAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except UniqueViolation:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "El usuario asociado ya pertenece "
                "a otro paciente"
            ),
        )

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.delete(
    "/pacientes/{numero_documento}",
    response_model=PacienteOut,
    tags=["Pacientes"],
)
def eliminar_paciente(
    numero_documento: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_paciente_para_auditoria(
                cursor,
                numero_documento,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Paciente no encontrado",
            )

        if datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "El paciente ya está eliminado"
                ),
            )

        cursor.execute(
            """
            UPDATE pacientes
            SET
                is_deleted = TRUE,
                deleted_at = NOW(),
                deleted_by = %s,
                updated_at = NOW()
            WHERE numero_documento_paciente = %s;
            """,
            (
                usuario_actual[
                    "numero_documento_usuario"
                ],
                numero_documento,
            ),
        )

        datos_nuevos = (
            obtener_paciente_para_auditoria(
                cursor,
                numero_documento,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="pacientes",
            registro_id=numero_documento,
            accion="ELIMINAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.patch(
    "/pacientes/{numero_documento}/restaurar",
    response_model=PacienteOut,
    tags=["Pacientes"],
)
def restaurar_paciente(
    numero_documento: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_paciente_para_auditoria(
                cursor,
                numero_documento,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Paciente no encontrado",
            )

        if not datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "El paciente no está eliminado"
                ),
            )

        cursor.execute(
            """
            UPDATE pacientes
            SET
                is_deleted = FALSE,
                deleted_at = NULL,
                deleted_by = NULL,
                updated_at = NOW()
            WHERE numero_documento_paciente = %s;
            """,
            (numero_documento,),
        )

        datos_nuevos = (
            obtener_paciente_para_auditoria(
                cursor,
                numero_documento,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="pacientes",
            registro_id=numero_documento,
            accion="RESTAURAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


# BLOQUE_REPORTES_PREVIOS_V1
# REPORTES PREVIOS AL DESPLAZAMIENTO

from datetime import datetime
from decimal import Decimal

from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field


class ReportePrevioCreate(BaseModel):
    id_paciente: int = Field(gt=0)

    sintoma_principal: str = Field(
        min_length=1,
    )

    inicio_sintomas: datetime | None = None
    evolucion: str | None = None
    signos_alarma_presentes: bool = False
    descripcion_signos_alarma: str | None = None

    ubicacion_aproximada: str | None = Field(
        default=None,
        max_length=200,
    )

    municipio_origen: str | None = Field(
        default=None,
        max_length=100,
    )

    distancia_aproximada_km: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=10,
        decimal_places=2,
    )

    tiempo_desplazamiento_min: int | None = Field(
        default=None,
        ge=0,
    )


class ReportePrevioUpdate(BaseModel):
    sintoma_principal: str | None = Field(
        default=None,
        min_length=1,
    )

    inicio_sintomas: datetime | None = None
    evolucion: str | None = None
    signos_alarma_presentes: bool | None = None
    descripcion_signos_alarma: str | None = None

    ubicacion_aproximada: str | None = Field(
        default=None,
        max_length=200,
    )

    municipio_origen: str | None = Field(
        default=None,
        max_length=100,
    )

    distancia_aproximada_km: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=10,
        decimal_places=2,
    )

    tiempo_desplazamiento_min: int | None = Field(
        default=None,
        ge=0,
    )


class OrientacionInicialUpdate(BaseModel):
    orientacion_inicial: str = Field(
        min_length=1,
    )


class ReportePrevioOut(BaseModel):
    id_reporte: int
    id_paciente: int
    fecha_hora_reporte: datetime
    sintoma_principal: str
    inicio_sintomas: datetime | None
    evolucion: str | None
    signos_alarma_presentes: bool
    descripcion_signos_alarma: str | None
    ubicacion_aproximada: str | None
    municipio_origen: str | None
    distancia_aproximada_km: Decimal | None
    tiempo_desplazamiento_min: int | None
    orientacion_inicial: str | None
    registrado_por: int
    created_at: datetime | None
    updated_at: datetime | None
    is_deleted: bool


def obtener_reporte_para_auditoria(
    cursor,
    id_reporte,
):
    cursor.execute(
        """
        SELECT
            id_reporte,
            id_paciente,
            fecha_hora_reporte,
            sintoma_principal,
            inicio_sintomas,
            evolucion,
            signos_alarma_presentes,
            descripcion_signos_alarma,
            ubicacion_aproximada,
            municipio_origen,
            distancia_aproximada_km,
            tiempo_desplazamiento_min,
            orientacion_inicial,
            registrado_por,
            created_at,
            updated_at,
            is_deleted,
            deleted_at,
            deleted_by
        FROM reportes_previos
        WHERE id_reporte = %s;
        """,
        (id_reporte,),
    )

    reporte = cursor.fetchone()

    if reporte is None:
        return None

    return dict(reporte)


def validar_acceso_reporte(
    reporte,
    usuario_actual,
):
    rol_actual = usuario_actual["rol"]

    if rol_actual in {"Admin", "Medico"}:
        return

    if rol_actual == "Paciente":
        if (
            reporte["id_paciente"]
            != usuario_actual[
                "numero_documento_usuario"
            ]
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "El paciente solamente puede acceder "
                    "a sus propios reportes"
                ),
            )

        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            "No tiene permiso para acceder "
            "a reportes previos"
        ),
    )


@app.post(
    "/reportes-previos",
    response_model=ReportePrevioOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Reportes previos"],
)
def crear_reporte_previo(
    reporte: ReportePrevioCreate,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Paciente", "Admin")
    ),
):
    rol_actual = usuario_actual["rol"]
    documento_actual = usuario_actual[
        "numero_documento_usuario"
    ]

    if (
        rol_actual == "Paciente"
        and reporte.id_paciente != documento_actual
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "El paciente solamente puede crear "
                "reportes para sí mismo"
            ),
        )

    if (
        reporte.signos_alarma_presentes
        and not reporte.descripcion_signos_alarma
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Debe describir los signos de alarma"
            ),
        )

    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT numero_documento_paciente
            FROM pacientes
            WHERE numero_documento_paciente = %s
              AND is_deleted = FALSE;
            """,
            (reporte.id_paciente,),
        )

        if cursor.fetchone() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    "El paciente no existe o está eliminado"
                ),
            )

        cursor.execute(
            """
            INSERT INTO reportes_previos (
                id_paciente,
                fecha_hora_reporte,
                sintoma_principal,
                inicio_sintomas,
                evolucion,
                signos_alarma_presentes,
                descripcion_signos_alarma,
                ubicacion_aproximada,
                municipio_origen,
                distancia_aproximada_km,
                tiempo_desplazamiento_min,
                registrado_por
            )
            VALUES (
                %s, NOW(), %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s
            )
            RETURNING
                id_reporte,
                id_paciente,
                fecha_hora_reporte,
                sintoma_principal,
                inicio_sintomas,
                evolucion,
                signos_alarma_presentes,
                descripcion_signos_alarma,
                ubicacion_aproximada,
                municipio_origen,
                distancia_aproximada_km,
                tiempo_desplazamiento_min,
                orientacion_inicial,
                registrado_por,
                created_at,
                updated_at,
                is_deleted;
            """,
            (
                reporte.id_paciente,
                reporte.sintoma_principal,
                reporte.inicio_sintomas,
                reporte.evolucion,
                reporte.signos_alarma_presentes,
                reporte.descripcion_signos_alarma,
                reporte.ubicacion_aproximada,
                reporte.municipio_origen,
                reporte.distancia_aproximada_km,
                reporte.tiempo_desplazamiento_min,
                documento_actual,
            ),
        )

        reporte_creado = dict(
            cursor.fetchone()
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="reportes_previos",
            registro_id=reporte_creado["id_reporte"],
            accion="CREAR",
            realizado_por=documento_actual,
            datos_anteriores=None,
            datos_nuevos=reporte_creado,
        )

        db.commit()
        return reporte_creado

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.get(
    "/reportes-previos/mios",
    response_model=list[ReportePrevioOut],
    tags=["Reportes previos"],
)
def listar_mis_reportes(
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Paciente")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT
                id_reporte,
                id_paciente,
                fecha_hora_reporte,
                sintoma_principal,
                inicio_sintomas,
                evolucion,
                signos_alarma_presentes,
                descripcion_signos_alarma,
                ubicacion_aproximada,
                municipio_origen,
                distancia_aproximada_km,
                tiempo_desplazamiento_min,
                orientacion_inicial,
                registrado_por,
                created_at,
                updated_at,
                is_deleted
            FROM reportes_previos
            WHERE id_paciente = %s
              AND is_deleted = FALSE
            ORDER BY fecha_hora_reporte DESC;
            """,
            (
                usuario_actual[
                    "numero_documento_usuario"
                ],
            ),
        )

        return cursor.fetchall()

    finally:
        cursor.close()


@app.get(
    "/reportes-previos",
    response_model=list[ReportePrevioOut],
    tags=["Reportes previos"],
)
def listar_reportes_previos(
    incluir_eliminados: bool = False,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin", "Medico")
    ),
):
    if (
        incluir_eliminados
        and usuario_actual["rol"] != "Admin"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Solamente el Admin puede consultar "
                "reportes eliminados"
            ),
        )

    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT
                id_reporte,
                id_paciente,
                fecha_hora_reporte,
                sintoma_principal,
                inicio_sintomas,
                evolucion,
                signos_alarma_presentes,
                descripcion_signos_alarma,
                ubicacion_aproximada,
                municipio_origen,
                distancia_aproximada_km,
                tiempo_desplazamiento_min,
                orientacion_inicial,
                registrado_por,
                created_at,
                updated_at,
                is_deleted
            FROM reportes_previos
            WHERE (
                %s = TRUE
                OR is_deleted = FALSE
            )
            ORDER BY fecha_hora_reporte DESC;
            """,
            (incluir_eliminados,),
        )

        return cursor.fetchall()

    finally:
        cursor.close()


@app.get(
    "/reportes-previos/{id_reporte}",
    response_model=ReportePrevioOut,
    tags=["Reportes previos"],
)
def consultar_reporte_previo(
    id_reporte: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        obtener_usuario_actual
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        reporte = obtener_reporte_para_auditoria(
            cursor,
            id_reporte,
        )

    finally:
        cursor.close()

    if reporte is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reporte previo no encontrado",
        )

    validar_acceso_reporte(
        reporte,
        usuario_actual,
    )

    if (
        reporte["is_deleted"]
        and usuario_actual["rol"] != "Admin"
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Reporte previo no encontrado",
        )

    return reporte


@app.put(
    "/reportes-previos/{id_reporte}",
    response_model=ReportePrevioOut,
    tags=["Reportes previos"],
)
def editar_reporte_previo(
    id_reporte: int,
    cambios: ReportePrevioUpdate,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Paciente", "Admin")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_reporte_para_auditoria(
                cursor,
                id_reporte,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Reporte previo no encontrado",
            )

        if datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "No se puede editar un reporte eliminado"
                ),
            )

        if usuario_actual["rol"] == "Paciente":
            if (
                datos_anteriores["id_paciente"]
                != usuario_actual[
                    "numero_documento_usuario"
                ]
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "El paciente solamente puede editar "
                        "sus propios reportes"
                    ),
                )

        datos_actualizacion = cambios.model_dump(
            exclude_unset=True
        )

        if not datos_actualizacion:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "No se enviaron datos para actualizar"
                ),
            )

        if (
            "sintoma_principal" in datos_actualizacion
            and datos_actualizacion[
                "sintoma_principal"
            ] is None
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "El síntoma principal no puede ser nulo"
                ),
            )

        signos_efectivos = datos_actualizacion.get(
            "signos_alarma_presentes",
            datos_anteriores[
                "signos_alarma_presentes"
            ],
        )

        descripcion_efectiva = datos_actualizacion.get(
            "descripcion_signos_alarma",
            datos_anteriores[
                "descripcion_signos_alarma"
            ],
        )

        if signos_efectivos and not descripcion_efectiva:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Debe describir los signos de alarma"
                ),
            )

        columnas_permitidas = {
            "sintoma_principal",
            "inicio_sintomas",
            "evolucion",
            "signos_alarma_presentes",
            "descripcion_signos_alarma",
            "ubicacion_aproximada",
            "municipio_origen",
            "distancia_aproximada_km",
            "tiempo_desplazamiento_min",
        }

        asignaciones = []
        valores = []

        for columna, valor in datos_actualizacion.items():
            if columna not in columnas_permitidas:
                continue

            asignaciones.append(
                f"{columna} = %s"
            )
            valores.append(valor)

        if not asignaciones:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "No hay campos válidos para actualizar"
                ),
            )

        asignaciones.append("updated_at = NOW()")
        valores.append(id_reporte)

        cursor.execute(
            f"""
            UPDATE reportes_previos
            SET {", ".join(asignaciones)}
            WHERE id_reporte = %s;
            """,
            valores,
        )

        datos_nuevos = (
            obtener_reporte_para_auditoria(
                cursor,
                id_reporte,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="reportes_previos",
            registro_id=id_reporte,
            accion="EDITAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.patch(
    "/reportes-previos/{id_reporte}/orientacion",
    response_model=ReportePrevioOut,
    tags=["Reportes previos"],
)
def registrar_orientacion_inicial(
    id_reporte: int,
    orientacion: OrientacionInicialUpdate,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin", "Medico")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_reporte_para_auditoria(
                cursor,
                id_reporte,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Reporte previo no encontrado",
            )

        if datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "No se puede orientar un reporte eliminado"
                ),
            )

        cursor.execute(
            """
            UPDATE reportes_previos
            SET
                orientacion_inicial = %s,
                updated_at = NOW()
            WHERE id_reporte = %s;
            """,
            (
                orientacion.orientacion_inicial,
                id_reporte,
            ),
        )

        datos_nuevos = (
            obtener_reporte_para_auditoria(
                cursor,
                id_reporte,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="reportes_previos",
            registro_id=id_reporte,
            accion="EDITAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.delete(
    "/reportes-previos/{id_reporte}",
    response_model=ReportePrevioOut,
    tags=["Reportes previos"],
)
def eliminar_reporte_previo(
    id_reporte: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Paciente", "Admin")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_reporte_para_auditoria(
                cursor,
                id_reporte,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Reporte previo no encontrado",
            )

        if datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "El reporte previo ya está eliminado"
                ),
            )

        if usuario_actual["rol"] == "Paciente":
            if (
                datos_anteriores["id_paciente"]
                != usuario_actual[
                    "numero_documento_usuario"
                ]
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "El paciente solamente puede eliminar "
                        "sus propios reportes"
                    ),
                )

        cursor.execute(
            """
            UPDATE reportes_previos
            SET
                is_deleted = TRUE,
                deleted_at = NOW(),
                deleted_by = %s,
                updated_at = NOW()
            WHERE id_reporte = %s;
            """,
            (
                usuario_actual[
                    "numero_documento_usuario"
                ],
                id_reporte,
            ),
        )

        datos_nuevos = (
            obtener_reporte_para_auditoria(
                cursor,
                id_reporte,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="reportes_previos",
            registro_id=id_reporte,
            accion="ELIMINAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.patch(
    "/reportes-previos/{id_reporte}/restaurar",
    response_model=ReportePrevioOut,
    tags=["Reportes previos"],
)
def restaurar_reporte_previo(
    id_reporte: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_reporte_para_auditoria(
                cursor,
                id_reporte,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Reporte previo no encontrado",
            )

        if not datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "El reporte previo no está eliminado"
                ),
            )

        cursor.execute(
            """
            UPDATE reportes_previos
            SET
                is_deleted = FALSE,
                deleted_at = NULL,
                deleted_by = NULL,
                updated_at = NOW()
            WHERE id_reporte = %s;
            """,
            (id_reporte,),
        )

        datos_nuevos = (
            obtener_reporte_para_auditoria(
                cursor,
                id_reporte,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="reportes_previos",
            registro_id=id_reporte,
            accion="RESTAURAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


# BLOQUE_ENCUENTROS_TRIAGE_V1
# ENCUENTROS Y CLASIFICACIÓN DE TRIAGE

from datetime import datetime
from typing import Literal

from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field


EstadoEncuentro = Literal[
    "en_triage",
    "en_atencion",
    "en_observacion",
    "finalizado",
]


class EncuentroCreate(BaseModel):
    id_paciente: int = Field(gt=0)

    tipo_encuentro: str | None = Field(
        default="urgencias",
        max_length=50,
    )

    motivo_consulta: str = Field(
        min_length=1,
    )

    observaciones_generales: str | None = None


class TriageUpdate(BaseModel):
    nivel_triage: int = Field(
        ge=1,
        le=5,
    )

    dolor_escala: int | None = Field(
        default=None,
        ge=0,
        le=10,
    )

    observaciones_triage: str | None = None


class EncuentroOut(BaseModel):
    id_encuentro: int
    id_paciente: int
    fecha_hora_ingreso: datetime
    fecha_hora_fin: datetime | None
    tipo_encuentro: str | None
    servicio: str | None
    estado: str | None
    motivo_consulta: str | None
    observaciones_generales: str | None
    nivel_triage: int | None
    fecha_hora_triage: datetime | None
    dolor_escala: int | None
    observaciones_triage: str | None
    clasificado_por: int | None
    clasificacion_automatica: bool | None
    creado_por: int
    created_at: datetime | None
    updated_at: datetime | None
    is_deleted: bool


def obtener_encuentro_para_auditoria(
    cursor,
    id_encuentro,
):
    cursor.execute(
        """
        SELECT
            id_encuentro,
            id_paciente,
            fecha_hora_ingreso,
            fecha_hora_fin,
            tipo_encuentro,
            servicio,
            estado,
            motivo_consulta,
            observaciones_generales,
            nivel_triage,
            fecha_hora_triage,
            dolor_escala,
            observaciones_triage,
            clasificado_por,
            clasificacion_automatica,
            creado_por,
            created_at,
            updated_at,
            is_deleted,
            deleted_at,
            deleted_by
        FROM encuentros
        WHERE id_encuentro = %s;
        """,
        (id_encuentro,),
    )

    encuentro = cursor.fetchone()

    if encuentro is None:
        return None

    return dict(encuentro)


def validar_acceso_encuentro(
    encuentro,
    usuario_actual,
):
    rol_actual = usuario_actual["rol"]

    if rol_actual in {"Admin", "Medico"}:
        return

    if rol_actual == "Paciente":
        if (
            encuentro["id_paciente"]
            != usuario_actual[
                "numero_documento_usuario"
            ]
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    "El paciente solamente puede consultar "
                    "sus propios encuentros"
                ),
            )

        return

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            "No tiene permiso para acceder "
            "a información clínica"
        ),
    )


@app.post(
    "/encuentros",
    response_model=EncuentroOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Encuentros y triage"],
)
def crear_encuentro(
    encuentro: EncuentroCreate,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin", "Medico")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT numero_documento_paciente
            FROM pacientes
            WHERE numero_documento_paciente = %s
              AND is_deleted = FALSE;
            """,
            (encuentro.id_paciente,),
        )

        if cursor.fetchone() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    "El paciente no existe o está eliminado"
                ),
            )

        # Evitar dos encuentros activos simultáneos.
        cursor.execute(
            """
            SELECT id_encuentro
            FROM encuentros
            WHERE id_paciente = %s
              AND estado <> 'finalizado'
              AND is_deleted = FALSE;
            """,
            (encuentro.id_paciente,),
        )

        encuentro_activo = cursor.fetchone()

        if encuentro_activo is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "El paciente ya tiene un encuentro "
                    "activo en urgencias"
                ),
            )

        cursor.execute(
            """
            INSERT INTO encuentros (
                id_paciente,
                fecha_hora_ingreso,
                tipo_encuentro,
                servicio,
                estado,
                motivo_consulta,
                observaciones_generales,
                clasificacion_automatica,
                creado_por
            )
            VALUES (
                %s,
                NOW(),
                %s,
                'URGENCIAS',
                'en_triage',
                %s,
                %s,
                FALSE,
                %s
            )
            RETURNING
                id_encuentro,
                id_paciente,
                fecha_hora_ingreso,
                fecha_hora_fin,
                tipo_encuentro,
                servicio,
                estado,
                motivo_consulta,
                observaciones_generales,
                nivel_triage,
                fecha_hora_triage,
                dolor_escala,
                observaciones_triage,
                clasificado_por,
                clasificacion_automatica,
                creado_por,
                created_at,
                updated_at,
                is_deleted;
            """,
            (
                encuentro.id_paciente,
                encuentro.tipo_encuentro,
                encuentro.motivo_consulta,
                encuentro.observaciones_generales,
                usuario_actual[
                    "numero_documento_usuario"
                ],
            ),
        )

        encuentro_creado = dict(
            cursor.fetchone()
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="encuentros",
            registro_id=(
                encuentro_creado["id_encuentro"]
            ),
            accion="CREAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=None,
            datos_nuevos=encuentro_creado,
        )

        db.commit()
        return encuentro_creado

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.get(
    "/encuentros/mios",
    response_model=list[EncuentroOut],
    tags=["Encuentros y triage"],
)
def listar_mis_encuentros(
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Paciente")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT
                id_encuentro,
                id_paciente,
                fecha_hora_ingreso,
                fecha_hora_fin,
                tipo_encuentro,
                servicio,
                estado,
                motivo_consulta,
                observaciones_generales,
                nivel_triage,
                fecha_hora_triage,
                dolor_escala,
                observaciones_triage,
                clasificado_por,
                clasificacion_automatica,
                creado_por,
                created_at,
                updated_at,
                is_deleted
            FROM encuentros
            WHERE id_paciente = %s
              AND is_deleted = FALSE
            ORDER BY fecha_hora_ingreso DESC;
            """,
            (
                usuario_actual[
                    "numero_documento_usuario"
                ],
            ),
        )

        return cursor.fetchall()

    finally:
        cursor.close()


@app.get(
    "/encuentros",
    response_model=list[EncuentroOut],
    tags=["Encuentros y triage"],
)
def listar_encuentros(
    estado_encuentro: EstadoEncuentro | None = None,
    incluir_eliminados: bool = False,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin", "Medico")
    ),
):
    if (
        incluir_eliminados
        and usuario_actual["rol"] != "Admin"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Solamente el Admin puede consultar "
                "encuentros eliminados"
            ),
        )

    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT
                id_encuentro,
                id_paciente,
                fecha_hora_ingreso,
                fecha_hora_fin,
                tipo_encuentro,
                servicio,
                estado,
                motivo_consulta,
                observaciones_generales,
                nivel_triage,
                fecha_hora_triage,
                dolor_escala,
                observaciones_triage,
                clasificado_por,
                clasificacion_automatica,
                creado_por,
                created_at,
                updated_at,
                is_deleted
            FROM encuentros
            WHERE (
                %s IS NULL
                OR estado = %s
            )
              AND (
                %s = TRUE
                OR is_deleted = FALSE
            )
            ORDER BY
                nivel_triage ASC NULLS LAST,
                fecha_hora_ingreso ASC;
            """,
            (
                estado_encuentro,
                estado_encuentro,
                incluir_eliminados,
            ),
        )

        return cursor.fetchall()

    finally:
        cursor.close()


@app.get(
    "/encuentros/{id_encuentro}",
    response_model=EncuentroOut,
    tags=["Encuentros y triage"],
)
def consultar_encuentro(
    id_encuentro: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        obtener_usuario_actual
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        encuentro = obtener_encuentro_para_auditoria(
            cursor,
            id_encuentro,
        )

    finally:
        cursor.close()

    if encuentro is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Encuentro no encontrado",
        )

    validar_acceso_encuentro(
        encuentro,
        usuario_actual,
    )

    if (
        encuentro["is_deleted"]
        and usuario_actual["rol"] != "Admin"
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Encuentro no encontrado",
        )

    return encuentro


@app.put(
    "/encuentros/{id_encuentro}/triage",
    response_model=EncuentroOut,
    tags=["Encuentros y triage"],
)
def registrar_triage(
    id_encuentro: int,
    triage: TriageUpdate,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Medico")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_encuentro_para_auditoria(
                cursor,
                id_encuentro,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Encuentro no encontrado",
            )

        if datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "No se puede clasificar "
                    "un encuentro eliminado"
                ),
            )

        if datos_anteriores["estado"] == "finalizado":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "No se puede modificar el triage "
                    "de un encuentro finalizado"
                ),
            )

        cursor.execute(
            """
            UPDATE encuentros
            SET
                nivel_triage = %s,
                fecha_hora_triage = NOW(),
                dolor_escala = %s,
                observaciones_triage = %s,
                clasificado_por = %s,
                clasificacion_automatica = FALSE,
                estado = 'en_atencion',
                updated_at = NOW()
            WHERE id_encuentro = %s;
            """,
            (
                triage.nivel_triage,
                triage.dolor_escala,
                triage.observaciones_triage,
                usuario_actual[
                    "numero_documento_usuario"
                ],
                id_encuentro,
            ),
        )

        datos_nuevos = (
            obtener_encuentro_para_auditoria(
                cursor,
                id_encuentro,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="encuentros",
            registro_id=id_encuentro,
            accion="EDITAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.patch(
    "/encuentros/{id_encuentro}/finalizar",
    response_model=EncuentroOut,
    tags=["Encuentros y triage"],
)
def finalizar_encuentro(
    id_encuentro: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Medico")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_encuentro_para_auditoria(
                cursor,
                id_encuentro,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Encuentro no encontrado",
            )

        if datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "No se puede finalizar "
                    "un encuentro eliminado"
                ),
            )

        if datos_anteriores["estado"] == "finalizado":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "El encuentro ya está finalizado"
                ),
            )

        if datos_anteriores["nivel_triage"] is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "El encuentro debe tener una "
                    "clasificación de triage"
                ),
            )

        cursor.execute(
            """
            UPDATE encuentros
            SET
                estado = 'finalizado',
                fecha_hora_fin = NOW(),
                updated_at = NOW()
            WHERE id_encuentro = %s;
            """,
            (id_encuentro,),
        )

        datos_nuevos = (
            obtener_encuentro_para_auditoria(
                cursor,
                id_encuentro,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="encuentros",
            registro_id=id_encuentro,
            accion="EDITAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.delete(
    "/encuentros/{id_encuentro}",
    response_model=EncuentroOut,
    tags=["Encuentros y triage"],
)
def eliminar_encuentro(
    id_encuentro: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin", "Medico")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_encuentro_para_auditoria(
                cursor,
                id_encuentro,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Encuentro no encontrado",
            )

        if datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "El encuentro ya está eliminado"
                ),
            )

        if usuario_actual["rol"] == "Medico":
            if (
                datos_anteriores["creado_por"]
                != usuario_actual[
                    "numero_documento_usuario"
                ]
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "El Médico solamente puede eliminar "
                        "encuentros creados por él"
                    ),
                )

        cursor.execute(
            """
            UPDATE encuentros
            SET
                is_deleted = TRUE,
                deleted_at = NOW(),
                deleted_by = %s,
                updated_at = NOW()
            WHERE id_encuentro = %s;
            """,
            (
                usuario_actual[
                    "numero_documento_usuario"
                ],
                id_encuentro,
            ),
        )

        datos_nuevos = (
            obtener_encuentro_para_auditoria(
                cursor,
                id_encuentro,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="encuentros",
            registro_id=id_encuentro,
            accion="ELIMINAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.patch(
    "/encuentros/{id_encuentro}/restaurar",
    response_model=EncuentroOut,
    tags=["Encuentros y triage"],
)
def restaurar_encuentro(
    id_encuentro: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_encuentro_para_auditoria(
                cursor,
                id_encuentro,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Encuentro no encontrado",
            )

        if not datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "El encuentro no está eliminado"
                ),
            )

        cursor.execute(
            """
            UPDATE encuentros
            SET
                is_deleted = FALSE,
                deleted_at = NULL,
                deleted_by = NULL,
                updated_at = NOW()
            WHERE id_encuentro = %s;
            """,
            (id_encuentro,),
        )

        datos_nuevos = (
            obtener_encuentro_para_auditoria(
                cursor,
                id_encuentro,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="encuentros",
            registro_id=id_encuentro,
            accion="RESTAURAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


# BLOQUE_OBSERVACIONES_V1
# OBSERVACIONES CLÍNICAS

from datetime import datetime
from decimal import Decimal

from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field


class ObservacionCreate(BaseModel):
    id_encuentro: int = Field(gt=0)

    tipo_observacion: str = Field(
        min_length=1,
        max_length=30,
    )

    codigo_loinc: str | None = Field(
        default=None,
        max_length=100,
    )

    nombre: str = Field(
        min_length=1,
        max_length=150,
    )

    valor_numerico: Decimal | None = Field(
        default=None,
        max_digits=10,
        decimal_places=2,
    )
    valor_texto: str | None = None

    unidad: str | None = Field(
        default=None,
        max_length=30,
    )


class ObservacionUpdate(BaseModel):
    tipo_observacion: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
    )

    codigo_loinc: str | None = Field(
        default=None,
        max_length=30,
    )

    nombre: str | None = Field(
        default=None,
        min_length=1,
        max_length=150,
    )

    valor_numerico: Decimal | None = Field(
        default=None,
        max_digits=10,
        decimal_places=2,
    )
    valor_texto: str | None = None

    unidad: str | None = Field(
        default=None,
        max_length=30,
    )


class ObservacionOut(BaseModel):
    id_observacion: int
    id_encuentro: int
    tipo_observacion: str
    codigo_loinc: str | None
    nombre: str
    valor_numerico: Decimal | None
    valor_texto: str | None
    unidad: str | None
    fecha_hora_observacion: datetime
    registrado_por: int
    created_at: datetime | None
    updated_at: datetime | None
    is_deleted: bool


def obtener_observacion_para_auditoria(
    cursor,
    id_observacion,
):
    cursor.execute(
        """
        SELECT
            id_observacion,
            id_encuentro,
            tipo_observacion,
            codigo_loinc,
            nombre,
            valor_numerico,
            valor_texto,
            unidad,
            fecha_hora_observacion,
            registrado_por,
            created_at,
            updated_at,
            is_deleted,
            deleted_at,
            deleted_by
        FROM observaciones
        WHERE id_observacion = %s;
        """,
        (id_observacion,),
    )

    observacion = cursor.fetchone()

    if observacion is None:
        return None

    return dict(observacion)


def validar_valor_observacion(
    valor_numerico,
    valor_texto,
):
    if (
        valor_numerico is None
        and valor_texto is None
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Debe proporcionar un valor numérico "
                "o un valor textual"
            ),
        )

    if (
        valor_numerico is not None
        and valor_texto is not None
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "La observación no puede tener al mismo "
                "tiempo un valor numérico y uno textual"
            ),
        )


def validar_acceso_observacion(
    observacion,
    usuario_actual,
    cursor,
):
    encuentro = obtener_encuentro_para_auditoria(
        cursor,
        observacion["id_encuentro"],
    )

    if encuentro is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "El encuentro relacionado no existe"
            ),
        )

    validar_acceso_encuentro(
        encuentro,
        usuario_actual,
    )

    return encuentro


@app.post(
    "/observaciones",
    response_model=ObservacionOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Observaciones"],
)
def crear_observacion(
    observacion: ObservacionCreate,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Medico")
    ),
):
    validar_valor_observacion(
        observacion.valor_numerico,
        observacion.valor_texto,
    )

    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        encuentro = obtener_encuentro_para_auditoria(
            cursor,
            observacion.id_encuentro,
        )

        if encuentro is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Encuentro no encontrado",
            )

        if encuentro["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "No se pueden registrar observaciones "
                    "en un encuentro eliminado"
                ),
            )

        if encuentro["estado"] == "finalizado":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "No se pueden registrar observaciones "
                    "en un encuentro finalizado"
                ),
            )

        cursor.execute(
            """
            INSERT INTO observaciones (
                id_encuentro,
                tipo_observacion,
                codigo_loinc,
                nombre,
                valor_numerico,
                valor_texto,
                unidad,
                fecha_hora_observacion,
                registrado_por
            )
            VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, NOW(), %s
            )
            RETURNING
                id_observacion,
                id_encuentro,
                tipo_observacion,
                codigo_loinc,
                nombre,
                valor_numerico,
                valor_texto,
                unidad,
                fecha_hora_observacion,
                registrado_por,
                created_at,
                updated_at,
                is_deleted;
            """,
            (
                observacion.id_encuentro,
                observacion.tipo_observacion,
                observacion.codigo_loinc,
                observacion.nombre,
                observacion.valor_numerico,
                observacion.valor_texto,
                observacion.unidad,
                usuario_actual[
                    "numero_documento_usuario"
                ],
            ),
        )

        observacion_creada = dict(
            cursor.fetchone()
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="observaciones",
            registro_id=(
                observacion_creada[
                    "id_observacion"
                ]
            ),
            accion="CREAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=None,
            datos_nuevos=observacion_creada,
        )

        db.commit()
        return observacion_creada

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.get(
    "/encuentros/{id_encuentro}/observaciones",
    response_model=list[ObservacionOut],
    tags=["Observaciones"],
)
def listar_observaciones_encuentro(
    id_encuentro: int,
    incluir_eliminadas: bool = False,
    db=Depends(get_db),
    usuario_actual=Depends(
        obtener_usuario_actual
    ),
):
    if (
        incluir_eliminadas
        and usuario_actual["rol"] != "Admin"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Solamente el Admin puede consultar "
                "observaciones eliminadas"
            ),
        )

    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        encuentro = obtener_encuentro_para_auditoria(
            cursor,
            id_encuentro,
        )

        if encuentro is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Encuentro no encontrado",
            )

        validar_acceso_encuentro(
            encuentro,
            usuario_actual,
        )

        if (
            encuentro["is_deleted"]
            and usuario_actual["rol"] != "Admin"
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Encuentro no encontrado",
            )

        cursor.execute(
            """
            SELECT
                id_observacion,
                id_encuentro,
                tipo_observacion,
                codigo_loinc,
                nombre,
                valor_numerico,
                valor_texto,
                unidad,
                fecha_hora_observacion,
                registrado_por,
                created_at,
                updated_at,
                is_deleted
            FROM observaciones
            WHERE id_encuentro = %s
              AND (
                  %s = TRUE
                  OR is_deleted = FALSE
              )
            ORDER BY fecha_hora_observacion;
            """,
            (
                id_encuentro,
                incluir_eliminadas,
            ),
        )

        return cursor.fetchall()

    except HTTPException:
        raise

    finally:
        cursor.close()


@app.get(
    "/observaciones/{id_observacion}",
    response_model=ObservacionOut,
    tags=["Observaciones"],
)
def consultar_observacion(
    id_observacion: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        obtener_usuario_actual
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        observacion = (
            obtener_observacion_para_auditoria(
                cursor,
                id_observacion,
            )
        )

        if observacion is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Observación no encontrada",
            )

        validar_acceso_observacion(
            observacion,
            usuario_actual,
            cursor,
        )

    finally:
        cursor.close()

    if (
        observacion["is_deleted"]
        and usuario_actual["rol"] != "Admin"
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Observación no encontrada",
        )

    return observacion


@app.put(
    "/observaciones/{id_observacion}",
    response_model=ObservacionOut,
    tags=["Observaciones"],
)
def editar_observacion(
    id_observacion: int,
    cambios: ObservacionUpdate,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin", "Medico")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_observacion_para_auditoria(
                cursor,
                id_observacion,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Observación no encontrada",
            )

        if datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "No se puede editar una "
                    "observación eliminada"
                ),
            )

        if usuario_actual["rol"] == "Medico":
            if (
                datos_anteriores["registrado_por"]
                != usuario_actual[
                    "numero_documento_usuario"
                ]
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "El Médico solamente puede editar "
                        "observaciones registradas por él"
                    ),
                )

        datos_actualizacion = cambios.model_dump(
            exclude_unset=True
        )

        if not datos_actualizacion:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "No se enviaron datos para actualizar"
                ),
            )

        for campo in {
            "tipo_observacion",
            "nombre",
        }:
            if (
                campo in datos_actualizacion
                and datos_actualizacion[campo] is None
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"El campo {campo} no puede ser nulo"
                    ),
                )

        # Si se cambia el tipo de valor, limpiar el anterior.
        if (
            datos_actualizacion.get(
                "valor_numerico"
            ) is not None
            and "valor_texto" not in datos_actualizacion
        ):
            datos_actualizacion["valor_texto"] = None

        if (
            datos_actualizacion.get(
                "valor_texto"
            ) is not None
            and "valor_numerico" not in datos_actualizacion
        ):
            datos_actualizacion["valor_numerico"] = None

        valor_numerico_efectivo = (
            datos_actualizacion.get(
                "valor_numerico",
                datos_anteriores["valor_numerico"],
            )
        )

        valor_texto_efectivo = (
            datos_actualizacion.get(
                "valor_texto",
                datos_anteriores["valor_texto"],
            )
        )

        validar_valor_observacion(
            valor_numerico_efectivo,
            valor_texto_efectivo,
        )

        columnas_permitidas = {
            "tipo_observacion",
            "codigo_loinc",
            "nombre",
            "valor_numerico",
            "valor_texto",
            "unidad",
        }

        asignaciones = []
        valores = []

        for columna, valor in datos_actualizacion.items():
            if columna not in columnas_permitidas:
                continue

            asignaciones.append(
                f"{columna} = %s"
            )
            valores.append(valor)

        if not asignaciones:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "No hay campos válidos para actualizar"
                ),
            )

        asignaciones.append("updated_at = NOW()")
        valores.append(id_observacion)

        cursor.execute(
            f"""
            UPDATE observaciones
            SET {", ".join(asignaciones)}
            WHERE id_observacion = %s;
            """,
            valores,
        )

        datos_nuevos = (
            obtener_observacion_para_auditoria(
                cursor,
                id_observacion,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="observaciones",
            registro_id=id_observacion,
            accion="EDITAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.delete(
    "/observaciones/{id_observacion}",
    response_model=ObservacionOut,
    tags=["Observaciones"],
)
def eliminar_observacion(
    id_observacion: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin", "Medico")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_observacion_para_auditoria(
                cursor,
                id_observacion,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Observación no encontrada",
            )

        if datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "La observación ya está eliminada"
                ),
            )

        if usuario_actual["rol"] == "Medico":
            if (
                datos_anteriores["registrado_por"]
                != usuario_actual[
                    "numero_documento_usuario"
                ]
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=(
                        "El Médico solamente puede eliminar "
                        "observaciones registradas por él"
                    ),
                )

        cursor.execute(
            """
            UPDATE observaciones
            SET
                is_deleted = TRUE,
                deleted_at = NOW(),
                deleted_by = %s,
                updated_at = NOW()
            WHERE id_observacion = %s;
            """,
            (
                usuario_actual[
                    "numero_documento_usuario"
                ],
                id_observacion,
            ),
        )

        datos_nuevos = (
            obtener_observacion_para_auditoria(
                cursor,
                id_observacion,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="observaciones",
            registro_id=id_observacion,
            accion="ELIMINAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.patch(
    "/observaciones/{id_observacion}/restaurar",
    response_model=ObservacionOut,
    tags=["Observaciones"],
)
def restaurar_observacion(
    id_observacion: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        datos_anteriores = (
            obtener_observacion_para_auditoria(
                cursor,
                id_observacion,
            )
        )

        if datos_anteriores is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Observación no encontrada",
            )

        if not datos_anteriores["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "La observación no está eliminada"
                ),
            )

        cursor.execute(
            """
            UPDATE observaciones
            SET
                is_deleted = FALSE,
                deleted_at = NULL,
                deleted_by = NULL,
                updated_at = NOW()
            WHERE id_observacion = %s;
            """,
            (id_observacion,),
        )

        datos_nuevos = (
            obtener_observacion_para_auditoria(
                cursor,
                id_observacion,
            )
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="observaciones",
            registro_id=id_observacion,
            accion="RESTAURAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=datos_anteriores,
            datos_nuevos=datos_nuevos,
        )

        db.commit()
        return datos_nuevos

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


# BLOQUE_FACTURACION_V2
# FACTURACIÓN CON DETALLES Y TOTAL AUTOMÁTICO


from datetime import datetime
from decimal import Decimal

from psycopg2.errors import UniqueViolation
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field


class DetalleAdicionalCreate(BaseModel):
    concepto: str = Field(
        min_length=1,
        max_length=200,
    )
    cantidad: int = Field(
        default=1,
        gt=0,
    )
    valor_unitario: Decimal = Field(
        ge=0,
        max_digits=12,
        decimal_places=2,
    )


class FacturaCreateV2(BaseModel):
    id_encuentro: int = Field(gt=0)

    numero_factura: str = Field(
        min_length=1,
        max_length=50,
    )

    concepto: str | None = None

    detalles_adicionales: list[
        DetalleAdicionalCreate
    ] = Field(default_factory=list)


class FacturaDetalleOut(BaseModel):
    id_detalle: int
    id_prescripcion: int | None
    concepto: str
    cantidad: int
    valor_unitario: Decimal
    valor_total: Decimal


class FacturaOutV2(BaseModel):
    id_factura: int
    id_paciente: int
    id_encuentro: int
    numero_factura: str
    fecha_emision: datetime
    concepto: str | None
    total: Decimal | None
    estado: str | None
    creado_por: int
    created_at: datetime | None
    updated_at: datetime | None
    is_deleted: bool
    detalles: list[FacturaDetalleOut]


def obtener_detalles_factura(
    cursor,
    id_factura,
):
    cursor.execute(
        """
        SELECT
            id_detalle,
            id_prescripcion,
            concepto,
            cantidad,
            valor_unitario,
            valor_total
        FROM factura_detalle
        WHERE id_factura = %s
          AND is_deleted = FALSE
        ORDER BY id_detalle;
        """,
        (id_factura,),
    )

    return [
        dict(fila)
        for fila in cursor.fetchall()
    ]


def obtener_factura_v2(
    cursor,
    id_factura,
):
    cursor.execute(
        """
        SELECT
            id_factura,
            id_paciente,
            id_encuentro,
            numero_factura,
            fecha_emision,
            concepto,
            total,
            estado,
            creado_por,
            created_at,
            updated_at,
            is_deleted
        FROM facturas
        WHERE id_factura = %s;
        """,
        (id_factura,),
    )

    factura = cursor.fetchone()

    if factura is None:
        return None

    resultado = dict(factura)

    resultado["detalles"] = (
        obtener_detalles_factura(
            cursor,
            id_factura,
        )
    )

    return resultado


@app.post(
    "/facturas",
    response_model=FacturaOutV2,
    status_code=status.HTTP_201_CREATED,
    tags=["Facturación"],
)
def crear_factura(
    factura: FacturaCreateV2,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles(
            "Admin",
            "Administrativo",
        )
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT
                id_encuentro,
                id_paciente,
                estado,
                is_deleted
            FROM encuentros
            WHERE id_encuentro = %s;
            """,
            (factura.id_encuentro,),
        )

        encuentro = cursor.fetchone()

        if encuentro is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Encuentro no encontrado",
            )

        if encuentro["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El encuentro está eliminado",
            )

        if encuentro["estado"] != "finalizado":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "El encuentro debe estar finalizado "
                    "antes de generar la factura"
                ),
            )

        cursor.execute(
            """
            SELECT 1
            FROM facturas
            WHERE id_encuentro = %s
              AND is_deleted = FALSE
              AND estado <> 'anulada';
            """,
            (factura.id_encuentro,),
        )

        if cursor.fetchone() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "El encuentro ya tiene "
                    "una factura activa"
                ),
            )

        # Obtener medicamentos dispensados
        cursor.execute(
            """
            SELECT
                pr.id_prescripcion,
                pr.cantidad,
                m.nombre AS medicamento,
                m.precio_unitario
            FROM prescripciones AS pr
            INNER JOIN medicamentos AS m
                ON m.codigo_cum = pr.codigo_cum
            WHERE pr.id_encuentro = %s
              AND pr.estado = 'dispensada'
              AND pr.is_deleted = FALSE;
            """,
            (factura.id_encuentro,),
        )

        medicamentos = cursor.fetchall()

        medicamentos_sin_precio = [
            medicamento["medicamento"]
            for medicamento in medicamentos
            if medicamento["precio_unitario"] is None
        ]

        if medicamentos_sin_precio:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Hay medicamentos dispensados "
                    "sin precio registrado: "
                    + ", ".join(
                        medicamentos_sin_precio
                    )
                ),
            )

        if (
            not medicamentos
            and not factura.detalles_adicionales
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "La factura debe contener por lo "
                    "menos un medicamento o servicio"
                ),
            )

        # Crear encabezado inicialmente con total cero
        cursor.execute(
            """
            INSERT INTO facturas (
                id_paciente,
                id_encuentro,
                numero_factura,
                fecha_emision,
                concepto,
                total,
                estado,
                creado_por
            )
            VALUES (
                %s, %s, %s, NOW(),
                %s, 0, 'pendiente', %s
            )
            RETURNING id_factura;
            """,
            (
                encuentro["id_paciente"],
                factura.id_encuentro,
                factura.numero_factura,
                factura.concepto,
                usuario_actual[
                    "numero_documento_usuario"
                ],
            ),
        )

        id_factura = cursor.fetchone()[
            "id_factura"
        ]

        detalles_creados = []

        # Agregar medicamentos dispensados
        for medicamento in medicamentos:
            valor_total = (
                medicamento["cantidad"]
                * medicamento["precio_unitario"]
            )

            cursor.execute(
                """
                INSERT INTO factura_detalle (
                    id_factura,
                    id_prescripcion,
                    concepto,
                    cantidad,
                    valor_unitario,
                    valor_total
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s
                )
                RETURNING
                    id_detalle,
                    id_prescripcion,
                    concepto,
                    cantidad,
                    valor_unitario,
                    valor_total;
                """,
                (
                    id_factura,
                    medicamento["id_prescripcion"],
                    (
                        "Medicamento: "
                        + medicamento["medicamento"]
                    ),
                    medicamento["cantidad"],
                    medicamento["precio_unitario"],
                    valor_total,
                ),
            )

            detalles_creados.append(
                dict(cursor.fetchone())
            )

        # Agregar servicios adicionales
        for detalle in factura.detalles_adicionales:
            valor_total = (
                detalle.cantidad
                * detalle.valor_unitario
            )

            cursor.execute(
                """
                INSERT INTO factura_detalle (
                    id_factura,
                    id_prescripcion,
                    concepto,
                    cantidad,
                    valor_unitario,
                    valor_total
                )
                VALUES (
                    %s, NULL, %s, %s, %s, %s
                )
                RETURNING
                    id_detalle,
                    id_prescripcion,
                    concepto,
                    cantidad,
                    valor_unitario,
                    valor_total;
                """,
                (
                    id_factura,
                    detalle.concepto,
                    detalle.cantidad,
                    detalle.valor_unitario,
                    valor_total,
                ),
            )

            detalles_creados.append(
                dict(cursor.fetchone())
            )

        total_factura = sum(
            (
                detalle["valor_total"]
                for detalle in detalles_creados
            ),
            Decimal("0"),
        )

        cursor.execute(
            """
            UPDATE facturas
            SET
                total = %s,
                updated_at = NOW()
            WHERE id_factura = %s;
            """,
            (
                total_factura,
                id_factura,
            ),
        )

        factura_creada = obtener_factura_v2(
            cursor,
            id_factura,
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="facturas",
            registro_id=id_factura,
            accion="CREAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=None,
            datos_nuevos=factura_creada,
        )

        db.commit()
        return factura_creada

    except UniqueViolation:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "El número de factura "
                "ya está registrado"
            ),
        )

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.get(
    "/facturas",
    response_model=list[FacturaOutV2],
    tags=["Facturación"],
)
def listar_facturas(
    incluir_eliminadas: bool = False,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles(
            "Admin",
            "Administrativo",
        )
    ),
):
    if (
        incluir_eliminadas
        and usuario_actual["rol"] != "Admin"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Solamente el Admin puede consultar "
                "facturas eliminadas"
            ),
        )

    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT id_factura
            FROM facturas
            WHERE (
                %s = TRUE
                OR is_deleted = FALSE
            )
            ORDER BY fecha_emision DESC;
            """,
            (incluir_eliminadas,),
        )

        identificadores = [
            fila["id_factura"]
            for fila in cursor.fetchall()
        ]

        return [
            obtener_factura_v2(
                cursor,
                id_factura,
            )
            for id_factura in identificadores
        ]

    finally:
        cursor.close()


@app.get(
    "/facturas/{id_factura}",
    response_model=FacturaOutV2,
    tags=["Facturación"],
)
def consultar_factura(
    id_factura: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles(
            "Admin",
            "Administrativo",
        )
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        factura = obtener_factura_v2(
            cursor,
            id_factura,
        )

    finally:
        cursor.close()

    if factura is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Factura no encontrada",
        )

    if (
        factura["is_deleted"]
        and usuario_actual["rol"] != "Admin"
    ):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Factura no encontrada",
        )

    return factura


# BLOQUE_CONSULTA_AUDITORIA_V1
# CONSULTA DEL HISTORIAL DE AUDITORÍA

from datetime import datetime
from typing import Literal

from fastapi import Query
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel


TablaAuditoria = Literal[
    "usuarios",
    "pacientes",
    "reportes_previos",
    "encuentros",
    "observaciones",
    "facturas",
]


class AuditoriaOut(BaseModel):
    id_auditoria: int
    tabla_afectada: str
    registro_id: str
    accion: str
    datos_anteriores: dict | None
    datos_nuevos: dict | None
    realizado_por: int
    username: str | None
    rol: str | None
    fecha_hora: datetime


@app.get(
    "/auditoria",
    response_model=list[AuditoriaOut],
    tags=["Auditoría"],
)
def listar_auditoria(
    limite: int = Query(
        default=100,
        ge=1,
        le=200,
    ),
    desplazamiento: int = Query(
        default=0,
        ge=0,
    ),
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    """
    Lista los registros de auditoría más recientes.

    Solamente puede ser utilizado por el administrador.
    """
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT
                a.id_auditoria,
                a.tabla_afectada,
                a.registro_id,
                a.accion,
                a.datos_anteriores,
                a.datos_nuevos,
                a.realizado_por,
                u.username,
                r.nombre AS rol,
                a.fecha_hora
            FROM auditoria_cambios AS a
            LEFT JOIN usuarios AS u
                ON (
                    u.numero_documento_usuario
                    = a.realizado_por
                )
            LEFT JOIN roles AS r
                ON r.id_rol = u.id_rol
            ORDER BY
                a.fecha_hora DESC,
                a.id_auditoria DESC
            LIMIT %s
            OFFSET %s;
            """,
            (
                limite,
                desplazamiento,
            ),
        )

        return cursor.fetchall()

    finally:
        cursor.close()


@app.get(
    "/auditoria/{tabla}/{registro_id}",
    response_model=list[AuditoriaOut],
    tags=["Auditoría"],
)
def consultar_auditoria_registro(
    tabla: TablaAuditoria,
    registro_id: str,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    """
    Consulta todo el historial de un registro específico.
    """
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT
                a.id_auditoria,
                a.tabla_afectada,
                a.registro_id,
                a.accion,
                a.datos_anteriores,
                a.datos_nuevos,
                a.realizado_por,
                u.username,
                r.nombre AS rol,
                a.fecha_hora
            FROM auditoria_cambios AS a
            LEFT JOIN usuarios AS u
                ON (
                    u.numero_documento_usuario
                    = a.realizado_por
                )
            LEFT JOIN roles AS r
                ON r.id_rol = u.id_rol
            WHERE a.tabla_afectada = %s
              AND a.registro_id = %s
            ORDER BY
                a.fecha_hora ASC,
                a.id_auditoria ASC;
            """,
            (
                tabla,
                registro_id,
            ),
        )

        historial = cursor.fetchall()

    finally:
        cursor.close()

    if not historial:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "No se encontraron registros de auditoría "
                "para el elemento indicado"
            ),
        )

    return historial


# BLOQUE_PRESCRIPCIONES_V1
# MEDICAMENTOS Y PRESCRIPCIONES MÉDICAS


from datetime import datetime
from decimal import Decimal
from typing import Literal

from psycopg2.errors import UniqueViolation
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field


EstadoPrescripcion = Literal[
    "activa",
    "dispensada",
    "anulada",
]


class MedicamentoCreate(BaseModel):
    codigo_cum: str = Field(
        min_length=1,
        max_length=50,
    )
    nombre: str = Field(
        min_length=1,
        max_length=150,
    )
    principio_activo: str | None = Field(
        default=None,
        max_length=150,
    )
    concentracion: str | None = Field(
        default=None,
        max_length=100,
    )
    forma_farmaceutica: str | None = Field(
        default=None,
        max_length=100,
    )
    registro_sanitario: str | None = Field(
        default=None,
        max_length=100,
    )
    estado_cum: str | None = Field(
        default=None,
        max_length=30,
    )
    precio_unitario: Decimal = Field(
        ge=0,
        max_digits=12,
        decimal_places=2,
    )


class MedicamentoOut(MedicamentoCreate):
    pass


class PrescripcionCreate(BaseModel):
    id_encuentro: int = Field(gt=0)
    codigo_cum: str = Field(
        min_length=1,
        max_length=50,
    )
    dosis: str | None = Field(
        default=None,
        max_length=100,
    )
    frecuencia: str | None = Field(
        default=None,
        max_length=100,
    )
    via_administracion: str | None = Field(
        default=None,
        max_length=50,
    )
    cantidad: int = Field(gt=0)


class PrescripcionUpdate(BaseModel):
    dosis: str | None = Field(
        default=None,
        max_length=100,
    )
    frecuencia: str | None = Field(
        default=None,
        max_length=100,
    )
    via_administracion: str | None = Field(
        default=None,
        max_length=50,
    )
    cantidad: int | None = Field(
        default=None,
        gt=0,
    )


class PrescripcionOut(BaseModel):
    id_prescripcion: int
    id_encuentro: int
    id_paciente: int
    codigo_cum: str
    medicamento: str
    dosis: str | None
    frecuencia: str | None
    via_administracion: str | None
    cantidad: int
    prescrito_por: int
    fecha_prescripcion: datetime
    estado: str
    created_at: datetime | None
    updated_at: datetime | None
    is_deleted: bool


def obtener_prescripcion_bd(
    cursor,
    id_prescripcion,
):
    cursor.execute(
        """
        SELECT
            pr.id_prescripcion,
            pr.id_encuentro,
            e.id_paciente,
            pr.codigo_cum,
            m.nombre AS medicamento,
            pr.dosis,
            pr.frecuencia,
            pr.via_administracion,
            pr.cantidad,
            pr.prescrito_por,
            pr.fecha_prescripcion,
            pr.estado,
            pr.created_at,
            pr.updated_at,
            pr.is_deleted
        FROM prescripciones AS pr
        INNER JOIN encuentros AS e
            ON e.id_encuentro = pr.id_encuentro
        INNER JOIN medicamentos AS m
            ON m.codigo_cum = pr.codigo_cum
        WHERE pr.id_prescripcion = %s;
        """,
        (id_prescripcion,),
    )

    resultado = cursor.fetchone()

    if resultado is None:
        return None

    return dict(resultado)


def validar_acceso_prescripcion(
    cursor,
    prescripcion,
    usuario_actual,
):
    if usuario_actual["rol"] != "Paciente":
        return

    cursor.execute(
        """
        SELECT 1
        FROM pacientes
        WHERE numero_documento_paciente = %s
          AND id_usuario = %s
          AND is_deleted = FALSE;
        """,
        (
            prescripcion["id_paciente"],
            usuario_actual[
                "numero_documento_usuario"
            ],
        ),
    )

    if cursor.fetchone() is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "El paciente solamente puede consultar "
                "sus propias prescripciones"
            ),
        )


@app.post(
    "/medicamentos",
    response_model=MedicamentoOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Medicamentos"],
)
def crear_medicamento(
    medicamento: MedicamentoCreate,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            INSERT INTO medicamentos (
                codigo_cum,
                nombre,
                principio_activo,
                concentracion,
                forma_farmaceutica,
                registro_sanitario,
                estado_cum,
                precio_unitario
            )
            VALUES (
                %s, %s, %s, %s,
                %s, %s, %s, %s
            )
            RETURNING *;
            """,
            (
                medicamento.codigo_cum,
                medicamento.nombre,
                medicamento.principio_activo,
                medicamento.concentracion,
                medicamento.forma_farmaceutica,
                medicamento.registro_sanitario,
                medicamento.estado_cum,
                medicamento.precio_unitario,
            ),
        )

        creado = dict(cursor.fetchone())

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="medicamentos",
            registro_id=creado["codigo_cum"],
            accion="CREAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=None,
            datos_nuevos=creado,
        )

        db.commit()
        return creado

    except UniqueViolation:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El código CUM ya está registrado",
        )

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.get(
    "/medicamentos",
    response_model=list[MedicamentoOut],
    tags=["Medicamentos"],
)
def listar_medicamentos(
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles(
            "Admin",
            "Medico",
            "Administrativo",
        )
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT *
            FROM medicamentos
            ORDER BY nombre;
            """
        )

        return cursor.fetchall()

    finally:
        cursor.close()


@app.get(
    "/medicamentos/{codigo_cum}",
    response_model=MedicamentoOut,
    tags=["Medicamentos"],
)
def consultar_medicamento(
    codigo_cum: str,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles(
            "Admin",
            "Medico",
            "Administrativo",
        )
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT *
            FROM medicamentos
            WHERE codigo_cum = %s;
            """,
            (codigo_cum,),
        )

        medicamento = cursor.fetchone()

    finally:
        cursor.close()

    if medicamento is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Medicamento no encontrado",
        )

    return medicamento


@app.post(
    "/prescripciones",
    response_model=PrescripcionOut,
    status_code=status.HTTP_201_CREATED,
    tags=["Prescripciones"],
)
def crear_prescripcion(
    prescripcion: PrescripcionCreate,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Medico")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        cursor.execute(
            """
            SELECT
                id_encuentro,
                estado,
                nivel_triage,
                is_deleted
            FROM encuentros
            WHERE id_encuentro = %s;
            """,
            (prescripcion.id_encuentro,),
        )

        encuentro = cursor.fetchone()

        if encuentro is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Encuentro no encontrado",
            )

        if encuentro["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El encuentro está eliminado",
            )

        if encuentro["estado"] == "finalizado":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El encuentro ya finalizó",
            )

        if encuentro["nivel_triage"] is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Primero se debe registrar "
                    "el triage presencial"
                ),
            )

        cursor.execute(
            """
            SELECT 1
            FROM medicamentos
            WHERE codigo_cum = %s;
            """,
            (prescripcion.codigo_cum,),
        )

        if cursor.fetchone() is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Medicamento no encontrado",
            )

        cursor.execute(
            """
            SELECT 1
            FROM prescripciones
            WHERE id_encuentro = %s
              AND codigo_cum = %s
              AND estado = 'activa'
              AND is_deleted = FALSE;
            """,
            (
                prescripcion.id_encuentro,
                prescripcion.codigo_cum,
            ),
        )

        if cursor.fetchone() is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Ya existe una prescripción activa "
                    "de ese medicamento"
                ),
            )

        cursor.execute(
            """
            INSERT INTO prescripciones (
                id_encuentro,
                codigo_cum,
                dosis,
                frecuencia,
                via_administracion,
                cantidad,
                prescrito_por,
                estado
            )
            VALUES (
                %s, %s, %s, %s,
                %s, %s, %s, 'activa'
            )
            RETURNING id_prescripcion;
            """,
            (
                prescripcion.id_encuentro,
                prescripcion.codigo_cum,
                prescripcion.dosis,
                prescripcion.frecuencia,
                prescripcion.via_administracion,
                prescripcion.cantidad,
                usuario_actual[
                    "numero_documento_usuario"
                ],
            ),
        )

        id_creado = cursor.fetchone()[
            "id_prescripcion"
        ]

        creado = obtener_prescripcion_bd(
            cursor,
            id_creado,
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="prescripciones",
            registro_id=id_creado,
            accion="CREAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=None,
            datos_nuevos=creado,
        )

        db.commit()
        return creado

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.get(
    "/prescripciones",
    response_model=list[PrescripcionOut],
    tags=["Prescripciones"],
)
def listar_prescripciones(
    id_encuentro: int | None = None,
    incluir_eliminadas: bool = False,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles(
            "Admin",
            "Medico",
            "Paciente",
        )
    ),
):
    if (
        incluir_eliminadas
        and usuario_actual["rol"] != "Admin"
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Solamente el Admin puede consultar "
                "prescripciones eliminadas"
            ),
        )

    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        condiciones = [
            "(%s = TRUE OR pr.is_deleted = FALSE)"
        ]
        valores = [incluir_eliminadas]

        if id_encuentro is not None:
            condiciones.append(
                "pr.id_encuentro = %s"
            )
            valores.append(id_encuentro)

        if usuario_actual["rol"] == "Paciente":
            condiciones.append(
                "p.id_usuario = %s"
            )
            valores.append(
                usuario_actual[
                    "numero_documento_usuario"
                ]
            )

        cursor.execute(
            f"""
            SELECT
                pr.id_prescripcion,
                pr.id_encuentro,
                e.id_paciente,
                pr.codigo_cum,
                m.nombre AS medicamento,
                pr.dosis,
                pr.frecuencia,
                pr.via_administracion,
                pr.cantidad,
                pr.prescrito_por,
                pr.fecha_prescripcion,
                pr.estado,
                pr.created_at,
                pr.updated_at,
                pr.is_deleted
            FROM prescripciones AS pr
            INNER JOIN encuentros AS e
                ON e.id_encuentro = pr.id_encuentro
            INNER JOIN pacientes AS p
                ON p.numero_documento_paciente
                 = e.id_paciente
            INNER JOIN medicamentos AS m
                ON m.codigo_cum = pr.codigo_cum
            WHERE {" AND ".join(condiciones)}
            ORDER BY pr.fecha_prescripcion DESC;
            """,
            valores,
        )

        return cursor.fetchall()

    finally:
        cursor.close()


@app.get(
    "/encuentros/{id_encuentro}/prescripciones",
    response_model=list[PrescripcionOut],
    tags=["Prescripciones"],
)
def listar_prescripciones_encuentro(
    id_encuentro: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles(
            "Admin",
            "Medico",
            "Paciente",
        )
    ),
):
    return listar_prescripciones(
        id_encuentro=id_encuentro,
        incluir_eliminadas=False,
        db=db,
        usuario_actual=usuario_actual,
    )


@app.get(
    "/prescripciones/{id_prescripcion}",
    response_model=PrescripcionOut,
    tags=["Prescripciones"],
)
def consultar_prescripcion(
    id_prescripcion: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles(
            "Admin",
            "Medico",
            "Paciente",
        )
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        prescripcion = obtener_prescripcion_bd(
            cursor,
            id_prescripcion,
        )

        if prescripcion is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Prescripción no encontrada",
            )

        if (
            prescripcion["is_deleted"]
            and usuario_actual["rol"] != "Admin"
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Prescripción no encontrada",
            )

        validar_acceso_prescripcion(
            cursor,
            prescripcion,
            usuario_actual,
        )

        return prescripcion

    finally:
        cursor.close()


@app.put(
    "/prescripciones/{id_prescripcion}",
    response_model=PrescripcionOut,
    tags=["Prescripciones"],
)
def editar_prescripcion(
    id_prescripcion: int,
    cambios: PrescripcionUpdate,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Medico")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        anterior = obtener_prescripcion_bd(
            cursor,
            id_prescripcion,
        )

        if anterior is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Prescripción no encontrada",
            )

        if (
            anterior["is_deleted"]
            or anterior["estado"] != "activa"
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "Solamente se puede editar "
                    "una prescripción activa"
                ),
            )

        datos = cambios.model_dump(
            exclude_unset=True
        )

        if not datos:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No se enviaron cambios",
            )

        asignaciones = [
            f"{campo} = %s"
            for campo in datos
        ]

        valores = (
            list(datos.values())
            + [id_prescripcion]
        )

        cursor.execute(
            f"""
            UPDATE prescripciones
            SET
                {", ".join(asignaciones)},
                updated_at = NOW()
            WHERE id_prescripcion = %s;
            """,
            valores,
        )

        nuevo = obtener_prescripcion_bd(
            cursor,
            id_prescripcion,
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="prescripciones",
            registro_id=id_prescripcion,
            accion="EDITAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=anterior,
            datos_nuevos=nuevo,
        )

        db.commit()
        return nuevo

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


def cambiar_estado_prescripcion(
    id_prescripcion,
    nuevo_estado,
    db,
    usuario_actual,
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        anterior = obtener_prescripcion_bd(
            cursor,
            id_prescripcion,
        )

        if anterior is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Prescripción no encontrada",
            )

        if (
            anterior["is_deleted"]
            or anterior["estado"] != "activa"
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "La prescripción no se "
                    "encuentra activa"
                ),
            )

        cursor.execute(
            """
            UPDATE prescripciones
            SET
                estado = %s,
                updated_at = NOW()
            WHERE id_prescripcion = %s;
            """,
            (
                nuevo_estado,
                id_prescripcion,
            ),
        )

        nuevo = obtener_prescripcion_bd(
            cursor,
            id_prescripcion,
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="prescripciones",
            registro_id=id_prescripcion,
            accion=nuevo_estado.upper(),
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=anterior,
            datos_nuevos=nuevo,
        )

        db.commit()
        return nuevo

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.patch(
    "/prescripciones/{id_prescripcion}/dispensar",
    response_model=PrescripcionOut,
    tags=["Prescripciones"],
)
def dispensar_prescripcion(
    id_prescripcion: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Medico")
    ),
):
    return cambiar_estado_prescripcion(
        id_prescripcion=id_prescripcion,
        nuevo_estado="dispensada",
        db=db,
        usuario_actual=usuario_actual,
    )


@app.patch(
    "/prescripciones/{id_prescripcion}/anular",
    response_model=PrescripcionOut,
    tags=["Prescripciones"],
)
def anular_prescripcion(
    id_prescripcion: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Medico")
    ),
):
    return cambiar_estado_prescripcion(
        id_prescripcion=id_prescripcion,
        nuevo_estado="anulada",
        db=db,
        usuario_actual=usuario_actual,
    )


@app.delete(
    "/prescripciones/{id_prescripcion}",
    response_model=PrescripcionOut,
    tags=["Prescripciones"],
)
def eliminar_prescripcion(
    id_prescripcion: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles(
            "Admin",
            "Medico",
        )
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        anterior = obtener_prescripcion_bd(
            cursor,
            id_prescripcion,
        )

        if anterior is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Prescripción no encontrada",
            )

        if anterior["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "La prescripción ya está eliminada"
                ),
            )

        cursor.execute(
            """
            UPDATE prescripciones
            SET
                is_deleted = TRUE,
                deleted_at = NOW(),
                deleted_by = %s,
                updated_at = NOW()
            WHERE id_prescripcion = %s;
            """,
            (
                usuario_actual[
                    "numero_documento_usuario"
                ],
                id_prescripcion,
            ),
        )

        nuevo = obtener_prescripcion_bd(
            cursor,
            id_prescripcion,
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="prescripciones",
            registro_id=id_prescripcion,
            accion="ELIMINAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=anterior,
            datos_nuevos=nuevo,
        )

        db.commit()
        return nuevo

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()


@app.patch(
    "/prescripciones/{id_prescripcion}/restaurar",
    response_model=PrescripcionOut,
    tags=["Prescripciones"],
)
def restaurar_prescripcion(
    id_prescripcion: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin")
    ),
):
    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        anterior = obtener_prescripcion_bd(
            cursor,
            id_prescripcion,
        )

        if anterior is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Prescripción no encontrada",
            )

        if not anterior["is_deleted"]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "La prescripción no está eliminada"
                ),
            )

        cursor.execute(
            """
            UPDATE prescripciones
            SET
                is_deleted = FALSE,
                deleted_at = NULL,
                deleted_by = NULL,
                updated_at = NOW()
            WHERE id_prescripcion = %s;
            """,
            (id_prescripcion,),
        )

        nuevo = obtener_prescripcion_bd(
            cursor,
            id_prescripcion,
        )

        registrar_auditoria(
            cursor=cursor,
            tabla_afectada="prescripciones",
            registro_id=id_prescripcion,
            accion="RESTAURAR",
            realizado_por=usuario_actual[
                "numero_documento_usuario"
            ],
            datos_anteriores=anterior,
            datos_nuevos=nuevo,
        )

        db.commit()
        return nuevo

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        raise

    finally:
        cursor.close()

# ============================================================
# INTEGRACIÓN FHIR R4 - PACIENTES
# ============================================================

@app.post(
    "/fhir/pacientes/{numero_documento}",
    tags=["FHIR - Patient"],
)
def enviar_paciente_a_fhir(
    numero_documento: int,
    db=Depends(get_db),
    usuario_actual=Depends(
        requerir_roles("Admin", "Medico")
    ),
):
    """
    Consulta un paciente en Neon y lo crea en HAPI FHIR
    como recurso Patient.
    """

    cursor = db.cursor(
        cursor_factory=RealDictCursor
    )

    try:
        # 1. Buscar paciente en PostgreSQL
        cursor.execute(
            """
            SELECT
                numero_documento_paciente,
                tipo_documento,
                nombres,
                apellidos,
                fecha_nacimiento,
                sexo,
                telefono,
                direccion,
                municipio_residencia,
                zona_residencia
            FROM pacientes
            WHERE numero_documento_paciente = %s
              AND is_deleted = FALSE;
            """,
            (numero_documento,),
        )

        paciente = cursor.fetchone()

    finally:
        cursor.close()

    # 2. Verificar que exista
    if paciente is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Paciente no encontrado o eliminado",
        )

    # 3. Identificador que relacionará Neon con FHIR
    sistema_identificador = (
        "urn:hospital-san-andres-tumaco:"
        "documento"
    )

    # 4. Revisar si ya existe en HAPI FHIR
    respuesta_busqueda = requests.get(
        f"{HAPI_FHIR_URL}/Patient",
        params={
            "identifier": (
                f"{sistema_identificador}|"
                f"{numero_documento}"
            )
        },
        timeout=10,
    )

    if respuesta_busqueda.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                "No fue posible consultar "
                "HAPI FHIR"
            ),
        )

    bundle = respuesta_busqueda.json()

    # Si ya existe, no lo duplicamos
    if bundle.get("total", 0) > 0:
        paciente_fhir = (
            bundle["entry"][0]["resource"]
        )

        return {
            "mensaje": "El paciente ya existe en HAPI FHIR",
            "origen": "PostgreSQL Neon",
            "destino": "HAPI FHIR",
            "resourceType": "Patient",
            "fhir_id": paciente_fhir["id"],
            "patient": paciente_fhir,
        }

    # 5. Construir recurso FHIR Patient
    paciente_fhir = {
        "resourceType": "Patient",
        "identifier": [
            {
                "system": sistema_identificador,
                "value": str(
                    paciente[
                        "numero_documento_paciente"
                    ]
                ),
                "type": {
                    "coding": [
                        {
                            "system": (
                                "http://terminology.hl7.org/"
                                "CodeSystem/v2-0203"
                            ),
                            "code": "NIIP",
                            "display": (
                                "National unique "
                                "individual identifier"
                            ),
                        }
                    ]
                },
            }
        ],
        "name": [
            {
                "family": paciente["apellidos"],
                "given": [
                    paciente["nombres"]
                ],
            }
        ],
    }

    # 6. Fecha de nacimiento
    if paciente["fecha_nacimiento"]:
        paciente_fhir["birthDate"] = (
            paciente["fecha_nacimiento"].isoformat()
        )

    # 7. Sexo
    mapa_sexo = {
        "M": "male",
        "Masculino": "male",
        "F": "female",
        "Femenino": "female",
        "Otro": "other",
        "O": "other",
        "Indeterminado": "unknown",
    }

    if paciente["sexo"]:
        sexo_fhir = mapa_sexo.get(
            paciente["sexo"]
        )

        if sexo_fhir:
            paciente_fhir["gender"] = sexo_fhir

    # 8. Teléfono
    if paciente["telefono"]:
        paciente_fhir["telecom"] = [
            {
                "system": "phone",
                "value": paciente["telefono"],
                "use": "mobile",
            }
        ]

    # 9. Dirección
    if (
        paciente["direccion"]
        or paciente["municipio_residencia"]
    ):
        direccion_fhir = {
            "use": "home",
            "type": "physical",
        }

        if paciente["direccion"]:
            direccion_fhir["line"] = [
                paciente["direccion"]
            ]

        if paciente["municipio_residencia"]:
            direccion_fhir["city"] = (
                paciente["municipio_residencia"]
            )

        paciente_fhir["address"] = [
            direccion_fhir
        ]

    # 10. Enviar a HAPI FHIR
    respuesta_hapi = requests.post(
        f"{HAPI_FHIR_URL}/Patient",
        json=paciente_fhir,
        headers={
            "Content-Type": "application/fhir+json"
        },
        timeout=10,
    )

    # 11. Manejar errores
    if respuesta_hapi.status_code not in (
        200,
        201,
    ):
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={
                "mensaje": (
                    "HAPI FHIR rechazó "
                    "el recurso Patient"
                ),
                "respuesta_hapi": (
                    respuesta_hapi.text
                ),
            },
        )

    paciente_creado = respuesta_hapi.json()

    # 12. Respuesta de nuestra API
    return {
        "mensaje": (
            "Paciente enviado correctamente "
            "a HAPI FHIR"
        ),
        "origen": "PostgreSQL Neon",
        "destino": "HAPI FHIR",
        "resourceType": "Patient",
        "fhir_id": paciente_creado.get("id"),
        "patient": paciente_creado,
    }
# ============================================================
# INTEGRACIÓN FHIR R4 - HAPI FHIR
# ============================================================

# ------------------------------------------------------------
# GET PATIENT
# ------------------------------------------------------------

@app.get(
    "/fhir/pacientes/{numero_documento}",
    summary="Consultar paciente en HAPI FHIR",
    tags=["FHIR"]
)
def obtener_paciente_fhir(
    numero_documento: int,
    current_user=Depends(requerir_roles("Admin", "Medico", "Paciente"))
):

    try:
        response = requests.get(
            f"{HAPI_FHIR_URL}/Patient",
            params={
                "identifier": str(numero_documento)
            },
            headers={
                "Accept": "application/fhir+json"
            },
            timeout=10
        )

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Error consultando HAPI FHIR: {response.text}"
            )

        bundle = response.json()

        if bundle.get("total", 0) == 0:
            raise HTTPException(
                status_code=404,
                detail="Paciente no encontrado en HAPI FHIR"
            )

        return bundle

    except requests.RequestException as e:
        raise HTTPException(
            status_code=503,
            detail=f"No fue posible conectarse con HAPI FHIR: {str(e)}"
        )


# ------------------------------------------------------------
# POST ENCOUNTER
# ------------------------------------------------------------

@app.post(
    "/fhir/encuentros/{id_encuentro}",
    summary="Enviar encuentro a HAPI FHIR",
    tags=["FHIR"]
)
def crear_encuentro_fhir(
    id_encuentro: int,
    db=Depends(get_db),
    current_user=Depends(requerir_roles("Admin", "Medico"))
):

    cursor = db.cursor(cursor_factory=RealDictCursor)

    cursor.execute(
        """
        SELECT
            e.id_encuentro,
            e.id_paciente,
            e.fecha_hora_ingreso,
            e.fecha_hora_fin,
            e.tipo_encuentro,
            e.servicio,
            e.estado,
            e.motivo_consulta,
            e.observaciones_generales,
            e.nivel_triage,
            e.fecha_hora_triage
        FROM encuentros e
        WHERE e.id_encuentro = %s
          AND e.is_deleted = FALSE
        """,
        (id_encuentro,)
    )

    encuentro = cursor.fetchone()

    if not encuentro:
        raise HTTPException(
            status_code=404,
            detail="Encuentro no encontrado"
        )

    # Buscar paciente en HAPI usando su documento
    response_patient = requests.get(
        f"{HAPI_FHIR_URL}/Patient",
        params={
            "identifier": str(encuentro["id_paciente"])
        },
        headers={
            "Accept": "application/fhir+json"
        },
        timeout=10
    )

    if response_patient.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail="No fue posible consultar el paciente en HAPI FHIR"
        )

    patient_bundle = response_patient.json()

    if patient_bundle.get("total", 0) == 0:
        raise HTTPException(
            status_code=404,
            detail="El paciente debe existir primero en HAPI FHIR"
        )

    patient_id = (
        patient_bundle["entry"][0]["resource"]["id"]
    )

    # Construcción del recurso FHIR Encounter
    encounter_fhir = {
        "resourceType": "Encounter",
        "identifier": [
        {
            "system": "https://hospital-san-andres-tumaco.co/encuentros",
            "value": str(id_encuentro)
        }],
        "status": "in-progress",
        "class": {
            "system": "http://terminology.hl7.org/CodeSystem/v3-ActCode",
            "code": "EMER",
            "display": "Emergency"
        },
        "subject": {
            "reference": f"Patient/{patient_id}"
        },
        "period": {
            "start": (
                encuentro["fecha_hora_ingreso"].isoformat()
                if encuentro["fecha_hora_ingreso"]
                else None
            )
        }
    }

    # Agregar motivo de consulta
    if encuentro["motivo_consulta"]:
        encounter_fhir["reasonCode"] = [
            {
                "text": encuentro["motivo_consulta"]
            }
        ]

    # Agregar servicio
    if encuentro["servicio"]:
        encounter_fhir["serviceType"] = {
            "text": encuentro["servicio"]
        }

    # Crear Encounter en HAPI
    response = requests.post(
        f"{HAPI_FHIR_URL}/Encounter",
        json=encounter_fhir,
        headers={
            "Content-Type": "application/fhir+json",
            "Accept": "application/fhir+json"
        },
        timeout=10
    )

    if response.status_code not in [200, 201]:
        raise HTTPException(
            status_code=502,
            detail=f"Error creando Encounter en HAPI: {response.text}"
        )

    return response.json()


# ------------------------------------------------------------
# GET ENCOUNTER
# ------------------------------------------------------------

@app.get(
    "/fhir/encuentros/{id_encuentro}",
    summary="Consultar encuentro en HAPI FHIR",
    tags=["FHIR"]
)
def obtener_encuentro_fhir(
    id_encuentro: int,
    current_user=Depends(requerir_roles("Admin", "Medico", "Paciente"))
):

    # Usamos el ID de nuestro encuentro como identificador externo
    response = requests.get(
        f"{HAPI_FHIR_URL}/Encounter",
        params={
            "identifier": str(id_encuentro)
        },
        headers={
            "Accept": "application/fhir+json"
        },
        timeout=10
    )

    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Error consultando HAPI FHIR: {response.text}"
        )

    bundle = response.json()

    if bundle.get("total", 0) == 0:
        raise HTTPException(
            status_code=404,
            detail="Encuentro no encontrado en HAPI FHIR"
        )

    return bundle


# ------------------------------------------------------------
# POST OBSERVATION
# ------------------------------------------------------------

@app.post(
    "/fhir/observaciones/{id_observacion}",
    summary="Enviar observación a HAPI FHIR",
    tags=["FHIR"]
)
def crear_observacion_fhir(
    id_observacion: int,
    db=Depends(get_db),
    current_user=Depends(requerir_roles("Admin", "Medico"))
):

    cursor = db.cursor(cursor_factory=RealDictCursor)

    cursor.execute(
        """
        SELECT
            o.id_observacion,
            o.id_encuentro,
            o.tipo_observacion,
            o.codigo_loinc,
            o.nombre,
            o.valor_numerico,
            o.valor_texto,
            o.unidad,
            o.fecha_hora_observacion
        FROM observaciones o
        WHERE o.id_observacion = %s
          AND o.is_deleted = FALSE
        """,
        (id_observacion,)
    )

    observacion = cursor.fetchone()

    if not observacion:
        raise HTTPException(
            status_code=404,
            detail="Observación no encontrada"
        )

    # Buscar Encounter en HAPI
    response_encounter = requests.get(
        f"{HAPI_FHIR_URL}/Encounter",
        params={
            "identifier": str(observacion["id_encuentro"])
        },
        headers={
            "Accept": "application/fhir+json"
        },
        timeout=10
    )

    if response_encounter.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail="No fue posible consultar el encuentro en HAPI FHIR"
        )

    encounter_bundle = response_encounter.json()

    if encounter_bundle.get("total", 0) == 0:
        raise HTTPException(
            status_code=404,
            detail="El encuentro debe existir primero en HAPI FHIR"
        )

    encounter_id = (
        encounter_bundle["entry"][0]["resource"]["id"]
    )

    # Construcción del recurso Observation
    observation_fhir = {
        "resourceType": "Observation",
         "identifier": [
        {
            "system": "https://hospital-san-andres-tumaco.co/observaciones",
            "value": str(id_observacion)
        }],
        "status": "final",
        "subject": {
            "reference": (
                encounter_bundle["entry"][0]["resource"]
                .get("subject", {})
                .get("reference")
            )
        },
        "encounter": {
            "reference": f"Encounter/{encounter_id}"
        }
    }

    # Código LOINC
    if observacion["codigo_loinc"]:
        observation_fhir["code"] = {
            "coding": [
                {
                    "system": "http://loinc.org",
                    "code": observacion["codigo_loinc"],
                    "display": observacion["nombre"]
                }
            ],
            "text": observacion["nombre"]
        }
    else:
        observation_fhir["code"] = {
            "text": observacion["nombre"]
        }

    # Fecha de observación
    if observacion["fecha_hora_observacion"]:
        observation_fhir["effectiveDateTime"] = (
            observacion["fecha_hora_observacion"].isoformat()
        )

    # Valor numérico
    if observacion["valor_numerico"] is not None:

        value_quantity = {
            "value": float(observacion["valor_numerico"])
        }

        if observacion["unidad"]:
            value_quantity["unit"] = observacion["unidad"]

        observation_fhir["valueQuantity"] = value_quantity

    # Valor textual
    elif observacion["valor_texto"]:

        observation_fhir["valueString"] = (
            observacion["valor_texto"]
        )

    # Crear Observation en HAPI
    response = requests.post(
        f"{HAPI_FHIR_URL}/Observation",
        json=observation_fhir,
        headers={
            "Content-Type": "application/fhir+json",
            "Accept": "application/fhir+json"
        },
        timeout=10
    )

    if response.status_code not in [200, 201]:
        raise HTTPException(
            status_code=502,
            detail=f"Error creando Observation en HAPI: {response.text}"
        )

    return response.json()


# ------------------------------------------------------------
# GET OBSERVATION
# ------------------------------------------------------------

@app.get(
    "/fhir/observaciones/{id_observacion}",
    summary="Consultar observación en HAPI FHIR",
    tags=["FHIR"]
)
def obtener_observacion_fhir(
    id_observacion: int,
    current_user=Depends(requerir_roles("Admin", "Medico", "Paciente"))
):

    response = requests.get(
        f"{HAPI_FHIR_URL}/Observation",
        params={
            "identifier": str(id_observacion)
        },
        headers={
            "Accept": "application/fhir+json"
        },
        timeout=10
    )

    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail=f"Error consultando HAPI FHIR: {response.text}"
        )

    bundle = response.json()

    if bundle.get("total", 0) == 0:
        raise HTTPException(
            status_code=404,
            detail="Observación no encontrada en HAPI FHIR"
        )

    return bundle