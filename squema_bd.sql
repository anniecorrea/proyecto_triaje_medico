
DROP TABLE IF EXISTS auditoria_cambios CASCADE;
DROP TABLE IF EXISTS factura_detalle CASCADE;
DROP TABLE IF EXISTS facturas CASCADE;
DROP TABLE IF EXISTS prescripciones CASCADE;
DROP TABLE IF EXISTS medicamentos CASCADE;
DROP TABLE IF EXISTS observaciones CASCADE;
DROP TABLE IF EXISTS encuentros CASCADE;
DROP TABLE IF EXISTS reportes_previos CASCADE;
DROP TABLE IF EXISTS antecedentes CASCADE;
DROP TABLE IF EXISTS pacientes CASCADE;
DROP TABLE IF EXISTS usuarios CASCADE;
DROP TABLE IF EXISTS roles CASCADE;


-- =====================================================================
-- 1. ROLES
-- =====================================================================

CREATE TABLE IF NOT EXISTS roles (
    id_rol SERIAL PRIMARY KEY,

    nombre VARCHAR(50) NOT NULL UNIQUE
        CHECK (
            nombre IN (
                'Admin',
                'Medico',
                'Administrativo',
                'Paciente'
            )
        ),

    descripcion TEXT,

    created_at TIMESTAMP DEFAULT now(),

    is_active BOOLEAN DEFAULT true
);

-- Roles iniciales requeridos para crear usuarios y aplicar control de acceso.
INSERT INTO roles (nombre, descripcion)
VALUES
    ('Admin', 'Administración general, gestión de usuarios y restauración de registros'),
    ('Medico', 'Consulta y gestión de la información clínica autorizada'),
    ('Administrativo', 'Gestión exclusiva de facturación y datos administrativos'),
    ('Paciente', 'Consulta de información propia y creación de reportes previos')
ON CONFLICT (nombre) DO NOTHING;


-- =====================================================================
-- 2. USUARIOS
-- =====================================================================

CREATE TABLE IF NOT EXISTS usuarios (
    numero_documento_usuario BIGINT PRIMARY KEY,

    id_rol INTEGER NOT NULL
        REFERENCES roles(id_rol),

    username VARCHAR(50) NOT NULL UNIQUE,

    password_hash TEXT NOT NULL,

    nombres VARCHAR(100) NOT NULL,

    apellidos VARCHAR(100) NOT NULL,

    email VARCHAR(150),

    telefono VARCHAR(20),

    estado BOOLEAN DEFAULT true,

    created_at TIMESTAMP DEFAULT now(),

    updated_at TIMESTAMP,

    is_deleted BOOLEAN DEFAULT false,

    deleted_at TIMESTAMP,

    deleted_by BIGINT
        REFERENCES usuarios(numero_documento_usuario)
);


-- =====================================================================
-- 3. AUDITORIA DE CAMBIOS
-- =====================================================================

CREATE TABLE IF NOT EXISTS auditoria_cambios (
    id_auditoria BIGSERIAL PRIMARY KEY,

    tabla_afectada VARCHAR(80) NOT NULL,

    registro_id VARCHAR(100) NOT NULL,

    accion VARCHAR(20) NOT NULL
        CHECK (
            accion IN (
                'CREAR',
                'EDITAR',
                'ELIMINAR',
                'RESTAURAR'
            )
        ),

    datos_anteriores JSONB,

    datos_nuevos JSONB,

    realizado_por BIGINT NOT NULL
        REFERENCES usuarios(numero_documento_usuario),

    fecha_hora TIMESTAMPTZ NOT NULL DEFAULT now()
);


-- =====================================================================
-- 4. PACIENTES
-- =====================================================================

CREATE TABLE IF NOT EXISTS pacientes (
    numero_documento_paciente BIGINT PRIMARY KEY,

    id_usuario BIGINT UNIQUE
        REFERENCES usuarios(numero_documento_usuario),

    tipo_documento VARCHAR(20) NOT NULL,

    nombres VARCHAR(100) NOT NULL,

    apellidos VARCHAR(100) NOT NULL,

    fecha_nacimiento DATE,

    sexo VARCHAR(20),

    telefono VARCHAR(20),

    direccion VARCHAR(200),

    municipio_residencia VARCHAR(100),

    zona_residencia VARCHAR(20)
        CHECK (
            zona_residencia IN (
                'urbana',
                'rural_dispersa'
            )
        ),

    created_at TIMESTAMP DEFAULT now(),

    updated_at TIMESTAMP,

    is_deleted BOOLEAN DEFAULT false,

    deleted_at TIMESTAMP,

    deleted_by BIGINT
        REFERENCES usuarios(numero_documento_usuario)
);


-- =====================================================================
-- 5. ANTECEDENTES
-- =====================================================================

CREATE TABLE IF NOT EXISTS antecedentes (
    id_antecedente SERIAL PRIMARY KEY,

    id_paciente BIGINT NOT NULL
        REFERENCES pacientes(numero_documento_paciente),

    tipo VARCHAR(50) NOT NULL,

    codigo VARCHAR(50),

    descripcion TEXT NOT NULL,

    fecha_registro TIMESTAMP DEFAULT now(),

    registrado_por BIGINT NOT NULL
        REFERENCES usuarios(numero_documento_usuario),

    is_deleted BOOLEAN DEFAULT false,

    deleted_at TIMESTAMP,

    deleted_by BIGINT
        REFERENCES usuarios(numero_documento_usuario)
);


-- =====================================================================
-- 6. REPORTES PREVIOS
-- Captura de información antes de llegar al hospital
-- =====================================================================

CREATE TABLE IF NOT EXISTS reportes_previos (
    id_reporte SERIAL PRIMARY KEY,

    id_paciente BIGINT NOT NULL
        REFERENCES pacientes(numero_documento_paciente),

    fecha_hora_reporte TIMESTAMP NOT NULL,

    sintoma_principal TEXT NOT NULL,

    inicio_sintomas TIMESTAMP,

    evolucion TEXT,

    signos_alarma_presentes BOOLEAN DEFAULT false,

    descripcion_signos_alarma TEXT,

    ubicacion_aproximada VARCHAR(200),

    municipio_origen VARCHAR(100),

    distancia_aproximada_km DECIMAL(10,2)
        CHECK (distancia_aproximada_km >= 0),

    tiempo_desplazamiento_min INTEGER
        CHECK (tiempo_desplazamiento_min >= 0),

    orientacion_inicial TEXT,

    registrado_por BIGINT NOT NULL
        REFERENCES usuarios(numero_documento_usuario),

    created_at TIMESTAMP DEFAULT now(),

    updated_at TIMESTAMP,

    is_deleted BOOLEAN DEFAULT false,

    deleted_at TIMESTAMP,

    deleted_by BIGINT
        REFERENCES usuarios(numero_documento_usuario)
);


-- =====================================================================
-- 7. ENCUENTROS
-- Mapea a FHIR Encounter
-- =====================================================================

CREATE TABLE IF NOT EXISTS encuentros (
    id_encuentro SERIAL PRIMARY KEY,

    id_paciente BIGINT NOT NULL
        REFERENCES pacientes(numero_documento_paciente),

    fecha_hora_ingreso TIMESTAMP NOT NULL,

    fecha_hora_fin TIMESTAMP,

    tipo_encuentro VARCHAR(50),

    servicio VARCHAR(50) DEFAULT 'URGENCIAS',

    estado VARCHAR(30)
        CHECK (
            estado IN (
                'en_triage',
                'en_atencion',
                'en_observacion',
                'finalizado'
            )
        ),

    motivo_consulta TEXT,

    observaciones_generales TEXT,

    nivel_triage SMALLINT
        CHECK (nivel_triage BETWEEN 1 AND 5),

    fecha_hora_triage TIMESTAMP,

    dolor_escala INTEGER
        CHECK (
            dolor_escala BETWEEN 0 AND 10
        ),

    observaciones_triage TEXT,


    -- Triage I:
    -- ingreso directo a reanimación.
    -- clasificado_por puede quedar NULL.

    clasificado_por BIGINT
        REFERENCES usuarios(numero_documento_usuario),

    clasificacion_automatica BOOLEAN DEFAULT false,


    creado_por BIGINT  NOT NULL
        REFERENCES usuarios(numero_documento_usuario),

    created_at TIMESTAMP DEFAULT now(),

    updated_at TIMESTAMP,

    is_deleted BOOLEAN DEFAULT false,

    deleted_at TIMESTAMP,

    deleted_by BIGINT
        REFERENCES usuarios(numero_documento_usuario)
);


-- =====================================================================
-- 8. OBSERVACIONES
-- Mapea a FHIR Observation
-- =====================================================================

CREATE TABLE IF NOT EXISTS observaciones (
    id_observacion SERIAL PRIMARY KEY,

    id_encuentro INTEGER NOT NULL
        REFERENCES encuentros(id_encuentro),

    tipo_observacion VARCHAR(100) NOT NULL,

    codigo_loinc VARCHAR(30),

    nombre VARCHAR(150) NOT NULL,

    valor_numerico DECIMAL(10,2),

    valor_texto TEXT,

    unidad VARCHAR(30),

    fecha_hora_observacion TIMESTAMP NOT NULL,

    registrado_por BIGINT NOT NULL
        REFERENCES usuarios(numero_documento_usuario),

    created_at TIMESTAMP DEFAULT now(),

    updated_at TIMESTAMP,

    is_deleted BOOLEAN DEFAULT false,

    deleted_at TIMESTAMP,

    deleted_by BIGINT
        REFERENCES usuarios(numero_documento_usuario)
);


-- =====================================================================
-- 9. MEDICAMENTOS
-- Catálogo de medicamentos identificado mediante CUM
-- =====================================================================

CREATE TABLE IF NOT EXISTS medicamentos (
    codigo_cum VARCHAR(50) PRIMARY KEY,

    nombre VARCHAR(150) NOT NULL,

    principio_activo VARCHAR(150),

    concentracion VARCHAR(100),

    forma_farmaceutica VARCHAR(100),

    registro_sanitario VARCHAR(100),

    estado_cum VARCHAR(30),

    precio_unitario DECIMAL(12,2)
        CHECK (precio_unitario >= 0)
);


-- =====================================================================
-- 10. PRESCRIPCIONES
-- Mapea a FHIR MedicationRequest
-- =====================================================================

CREATE TABLE IF NOT EXISTS prescripciones (
    id_prescripcion SERIAL PRIMARY KEY,

    id_encuentro INTEGER NOT NULL
        REFERENCES encuentros(id_encuentro),

    codigo_cum VARCHAR(50) NOT NULL
        REFERENCES medicamentos(codigo_cum),

    dosis VARCHAR(100),

    frecuencia VARCHAR(100),

    via_administracion VARCHAR(50),

    cantidad INTEGER NOT NULL
        CHECK (cantidad > 0),

    prescrito_por BIGINT NOT NULL
        REFERENCES usuarios(numero_documento_usuario),

    fecha_prescripcion TIMESTAMP NOT NULL DEFAULT now(),

    estado VARCHAR(30) DEFAULT 'activa'
        CHECK (
            estado IN (
                'activa',
                'dispensada',
                'anulada'
            )
        ),

    created_at TIMESTAMP DEFAULT now(),

    updated_at TIMESTAMP,

    is_deleted BOOLEAN DEFAULT false,

    deleted_at TIMESTAMP,

    deleted_by BIGINT
        REFERENCES usuarios(numero_documento_usuario)
);


-- =====================================================================
-- 11. FACTURAS
-- =====================================================================

CREATE TABLE IF NOT EXISTS facturas (
    id_factura SERIAL PRIMARY KEY,

    id_paciente BIGINT NOT NULL
        REFERENCES pacientes(numero_documento_paciente),

    id_encuentro INTEGER NOT NULL
        REFERENCES encuentros(id_encuentro),

    numero_factura VARCHAR(50) NOT NULL UNIQUE,

    fecha_emision TIMESTAMP NOT NULL,

    concepto TEXT,

    total DECIMAL(12,2)
        CHECK (total >= 0),

    estado VARCHAR(30)
        CHECK (
            estado IN (
                'pendiente',
                'pagada',
                'anulada'
            )
        ),

    creado_por BIGINT NOT NULL
        REFERENCES usuarios(numero_documento_usuario),

    created_at TIMESTAMP DEFAULT now(),

    updated_at TIMESTAMP,

    is_deleted BOOLEAN DEFAULT false,

    deleted_at TIMESTAMP,

    deleted_by BIGINT
        REFERENCES usuarios(numero_documento_usuario)
);


-- =====================================================================
-- 12. FACTURA_DETALLE
-- =====================================================================

CREATE TABLE IF NOT EXISTS factura_detalle (
    id_detalle SERIAL PRIMARY KEY,

    id_factura INTEGER NOT NULL
        REFERENCES facturas(id_factura),

    id_prescripcion INTEGER
        REFERENCES prescripciones(id_prescripcion),

    concepto VARCHAR(200) NOT NULL,

    cantidad INTEGER NOT NULL DEFAULT 1
        CHECK (cantidad > 0),

    valor_unitario DECIMAL(12,2) NOT NULL
        CHECK (valor_unitario >= 0),

    valor_total DECIMAL(12,2) NOT NULL
        CHECK (valor_total >= 0),

    created_at TIMESTAMP DEFAULT now(),

    is_deleted BOOLEAN DEFAULT false,

    deleted_at TIMESTAMP,

    deleted_by BIGINT
        REFERENCES usuarios(numero_documento_usuario)
);


-- =====================================================================
-- ÍNDICES
-- =====================================================================

CREATE INDEX idx_usuarios_id_rol
    ON usuarios(id_rol);

CREATE INDEX idx_pacientes_id_usuario
    ON pacientes(id_usuario);

CREATE INDEX idx_antecedentes_id_paciente
    ON antecedentes(id_paciente);

CREATE INDEX idx_reportes_previos_paciente
    ON reportes_previos(id_paciente);

CREATE INDEX idx_encuentros_id_paciente
    ON encuentros(id_paciente);

CREATE INDEX idx_observaciones_id_encuentro
    ON observaciones(id_encuentro);

CREATE INDEX idx_prescripciones_encuentro
    ON prescripciones(id_encuentro);

CREATE INDEX idx_prescripciones_medicamento
    ON prescripciones(codigo_cum);

CREATE INDEX idx_facturas_id_paciente
    ON facturas(id_paciente);

CREATE INDEX idx_facturas_id_encuentro
    ON facturas(id_encuentro);

CREATE INDEX idx_factura_detalle_id_factura
    ON factura_detalle(id_factura);

CREATE INDEX idx_auditoria_registro
    ON auditoria_cambios(tabla_afectada, registro_id);

CREATE INDEX idx_auditoria_usuario
    ON auditoria_cambios(realizado_por);

