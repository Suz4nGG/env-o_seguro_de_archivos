import os
def validarEntradasCliente( host, puerto, path_ref  ):
    if os.path.isdir(path_ref):
        print( 'Parámetros de entrada validos' )
    else:
        print( 'Directorio invalido, ingresa un directorio existente' )
        exit()

def validarEntradasServidor( puerto, path_ref ):
    if os.path.isdir(path_ref):
        print( 'Parámetros de entrada validos' )
    else:
        print( 'Directorio invalido, ingresa un directorio existente' )
        exit()