import pandas as pd
import ssl
import socket
from datetime import datetime, timedelta
from urllib.parse import urlparse
import sys

def get_certificate_info(domain):
    """
    Obtiene información del certificado SSL de un dominio.

    Args:
        domain (str): El dominio a analizar.

    Returns:
        dict: Un diccionario con la información del certificado.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        # Verificar si el certificado es comodín
        is_wildcard = cert['subject'][0][0][1].startswith('*') or any(
            x[1].startswith('*') for x in cert.get('subjectAltName', [])
        )

        # Verificar si el certificado es autofirmado
        is_self_signed = cert['issuer'] == cert['subject']

        # Extraer la fecha de expiración completa
        expiration_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")

        # Obtener el nombre de la organización emisora (organizationName) y el nombre común (commonName)
        issuer_org = dict(x[0] for x in cert['issuer']).get('organizationName', '')
        signer = dict(x[0] for x in cert['issuer']).get('commonName', '')

        return {
            'Fecha Expiracion': expiration_date,
            'Firmante': issuer_org,
            'Emisor': signer,
            'CN/Alt Names Coinciden': domain == cert['subject'][0][0][1] or domain in [x[1] for x in cert.get('subjectAltName', [])],
            'Es Comodín': "VERDADERO" if is_wildcard else "FALSO",
            'Es Autofirmado': "SI" if is_self_signed else "NO",
            'URL': f"https://{domain}"
        }

    except Exception as e:
        return {
            'Fecha Expiracion': "ERROR",
            'Firmante': "ERROR",
            'Emisor': str(e),
            'CN/Alt Names Coinciden': "ERROR",
            'Es Comodín': "ERROR",
            'Es Autofirmado': "ERROR",
            'URL': f"https://{domain}"
        }

def add_warning(df):
    """
    Agrega una columna de advertencia si el certificado está próximo a expirar.

    Args:
        df (pd.DataFrame): DataFrame con la información de los certificados.

    Returns:
        pd.DataFrame: DataFrame con la columna de advertencia.
    """
    warnings = []
    for _, row in df.iterrows():
        if isinstance(row['Fecha Expiracion'], datetime):
            # Verifica si la fecha de expiración está dentro de los próximos 15 dias //#3 meses//
            if row['Fecha Expiracion'] <= datetime.now() + timedelta(days=15):
                warnings.append("En menos de 15 dias expira el certificado")
            else:
                warnings.append("OK")
        else:
            warnings.append("ERROR")

    df['Advertencia'] = warnings
    return df

# Leer las URLs desde el archivo Excel
file_path = r"Archivo.xlxs"
df = pd.read_excel(file_path)
urls = df['URL'].tolist()

# Crear un DataFrame para almacenar los resultados
results_df = pd.DataFrame()

# Iterar sobre las URLs y obtener la información del certificado
for url in urls:
    domain = urlparse(url).hostname
    if ("www" in domain):
        cantidad_puntos = domain.count(".")
        if (cantidad_puntos > 2):
            domain = domain.replace("www.", "", 1)

    cert_info = get_certificate_info(domain)

    # Si ocurre el error de "getaddrinfo failed", intentar con el dominio sin el 'www.'
    if cert_info['Emisor'] == "[Errno 11001] getaddrinfo failed":
        # Intentar con la URL sin 'www.'
        domain_without_www = domain[4:] if domain.startswith('www.') else domain
        cert_info = get_certificate_info(domain_without_www)

    results_df = pd.concat([results_df, pd.DataFrame([cert_info])], ignore_index=True)

# Agregar la columna de advertencia
results_df = add_warning(results_df)

# Reorganizar las columnas en el orden deseado
results_df = results_df[['URL', 'Emisor', 'CN/Alt Names Coinciden', 'Es Comodín', 'Es Autofirmado', 'Firmante', 'Fecha Expiracion', 'Advertencia']]

# Asegurarse de que 'Fecha Expiracion' es de tipo datetime con el formato adecuado
results_df['Fecha Expiracion'] = pd.to_datetime(results_df['Fecha Expiracion'], format="%b %d %H:%M:%S %Y %Z", errors='coerce')

# Ordenar el DataFrame por la columna 'Fecha Expiracion' (de más cercana a más lejana)
results_df = results_df.sort_values(by='Fecha Expiracion', ascending=True)

# Filtrar resultados que no son OK
filtered_results_df = results_df[results_df['Advertencia'] != "OK"]

# Guardar los resultados en un archivo Excel
output_path = r"Certificados.xlsx"
#results_df.to_excel(output_path, index=False)
filtered_results_df.to_excel(output_path, index=False)

print("Análisis del certificado completado y guardado en 'Certificados.xlsx'")