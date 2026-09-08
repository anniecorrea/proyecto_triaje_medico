import os

import psycopg2
from psycopg2 import sql
from dotenv import load_dotenv


load_dotenv("pass.env", override=True)

conexion = psycopg2.connect(os.getenv("PG_CONNECTION_STRING"))
cursor = conexion.cursor()

print("\n1. CONEXIÓN")
cursor.execute("SELECT current_database(), current_user;")
print(cursor.fetchone())


print("\n2. TABLAS EXISTENTES")
cursor.execute("""
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = 'public'
    ORDER BY table_name;
""")

tablas = [fila[0] for fila in cursor.fetchall()]

for tabla in tablas:
    print("-", tabla)


print("\n3. CANTIDAD DE REGISTROS")
for tabla in tablas:
    consulta = sql.SQL("SELECT COUNT(*) FROM {};").format(
        sql.Identifier(tabla)
    )
    cursor.execute(consulta)
    cantidad = cursor.fetchone()[0]
    print(f"{tabla}: {cantidad}")


print("\n4. ROLES REGISTRADOS")
cursor.execute("""
    SELECT id_rol, nombre, descripcion, is_active
    FROM roles
    ORDER BY id_rol;
""")

roles = cursor.fetchall()

if roles:
    for rol in roles:
        print(rol)
else:
    print("La tabla roles existe, pero no contiene registros.")


print("\n5. RESTRICCIONES DE LA TABLA ROLES")
cursor.execute("""
    SELECT
        conname,
        pg_get_constraintdef(oid)
    FROM pg_constraint
    WHERE conrelid = 'roles'::regclass;
""")

for restriccion in cursor.fetchall():
    print(restriccion)


print("\n6. COLUMNAS IMPORTANTES")
tablas_revisar = (
    "usuarios",
    "pacientes",
    "encuentros",
    "observaciones",
    "auditoria_cambios",
)

cursor.execute("""
    SELECT
        table_name,
        column_name,
        data_type,
        is_nullable,
        column_default
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name IN %s
    ORDER BY table_name, ordinal_position;
""", (tablas_revisar,))

tabla_anterior = None

for tabla, columna, tipo, permite_null, valor_default in cursor.fetchall():
    if tabla != tabla_anterior:
        print(f"\n[{tabla}]")
        tabla_anterior = tabla

    print(
        f"{columna} | {tipo} | "
        f"nullable={permite_null} | default={valor_default}"
    )


print("\n7. RESTRICCIONES DE ENCUENTROS")
cursor.execute("""
    SELECT
        conname,
        pg_get_constraintdef(oid)
    FROM pg_constraint
    WHERE conrelid = 'encuentros'::regclass;
""")

for restriccion in cursor.fetchall():
    print(restriccion)


print("\n8. ÍNDICES DE OBSERVACIONES")
cursor.execute("""
    SELECT indexname, indexdef
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND tablename = 'observaciones'
    ORDER BY indexname;
""")

for indice in cursor.fetchall():
    print(indice)


cursor.close()
conexion.close()

print("\nInspección finalizada. No se modificó ningún dato.")