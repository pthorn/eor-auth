<%page args="status, data=None, message=None, detail=None" />
<%! import json %>
<!doctype html>
<html>
    <head>
        <meta charset="utf-8">
    </head>
    <body>
        % if status == 'error':
            <h1>Ошибка входа</h1>
            <h4>${message}</h4>
            <p>${detail}</p>
            <p><button onclick="notifyAndClose();">Закрыть</button></p>
        % endif

        <script type="text/javascript"><!--
            var success = ${str(status != 'error').lower()};

            var notifyAndClose = function () {
                if (!window.opener) {
                    location.url = '/';  // TODO depending on status=registration|logged-in
                    return;
                }

                var data = {
                    status: '${status}'
                % if data:
                    , data: ${json.dumps(data) | n}
                % endif
                };

                window.opener.postMessage(JSON.stringify(data), location.origin || '*'); // TODO
                window.close();
            };

            if (success) {
                notifyAndClose();
            }
        --></script>
    </body>
</html>