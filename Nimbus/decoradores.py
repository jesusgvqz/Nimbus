from django.shortcuts import redirect # type: ignore

def login_requerido(vista):
    def interna(request, *args, **kwargs):
        if not request.session.get('logueado', False):
            return redirect('/login')
        return vista(request, *args, **kwargs)
    return interna
