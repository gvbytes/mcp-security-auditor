import sys
import json

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            method = request.get('method')
            msg_id = request.get('id')
            if method == 'initialize':
                response = {'jsonrpc': '2.0', 'id': msg_id, 'result': {'protocolVersion': '2024-11-05', 'capabilities': {'tools': {}, 'resources': {}, 'prompts': {}}, 'serverInfo': {'name': 'VulnerableMockMCPServer', 'version': '1.0.0'}}}
            elif method == 'tools/list':
                response = {'jsonrpc': '2.0', 'id': msg_id, 'result': {'tools': [{'name': 'execute_shell', 'description': 'Runs arbitrary shell commands directly on the host machine.', 'inputSchema': {'type': 'object', 'properties': {'command': {'type': 'string', 'description': 'The exact shell command to execute.'}}, 'required': ['command']}}, {'name': 'update_system_config', 'description': 'Modifies critical host configuration files.', 'inputSchema': {'type': 'object', 'properties': {'path': {'type': 'string', 'description': 'Absolute target path to overwrite.'}, 'data': {'type': 'string'}}, 'required': ['path', 'data']}}, {'name': 'add_integers', 'description': 'Securely adds two integers.', 'inputSchema': {'type': 'object', 'properties': {'a': {'type': 'integer'}, 'b': {'type': 'integer'}}, 'required': ['a', 'b']}}]}}
            elif method == 'resources/list':
                response = {'jsonrpc': '2.0', 'id': msg_id, 'result': {'resources': [{'uri': 'file:///C:/Users/Jay%20Prakash%20Verma/.env', 'name': 'Secret Credentials', 'mimeType': 'text/plain'}, {'uri': 'file:///etc/passwd', 'name': 'System Users Directory', 'mimeType': 'text/plain'}, {'uri': 'file:///public/logo.png', 'name': 'Public Image Asset', 'mimeType': 'image/png'}]}}
            elif method == 'prompts/list':
                response = {'jsonrpc': '2.0', 'id': msg_id, 'result': {'prompts': [{'name': 'analyze_user_comment', 'description': 'Directly feeds raw untrusted user input into the context without framing.', 'arguments': [{'name': 'comment', 'description': 'User input comments to translate.', 'required': True}]}, {'name': 'secure_system_template', 'description': 'System template containing instructions to treat arguments as untrusted inputs.', 'arguments': [{'name': 'user_text', 'description': 'Untrusted text argument.', 'required': True}]}]}}
            else:
                response = {'jsonrpc': '2.0', 'id': msg_id, 'error': {'code': -32601, 'message': 'Method not found'}}
            sys.stdout.write(json.dumps(response) + '\n')
            sys.stdout.flush()
        except Exception as e:
            sys.stderr.write(f'Error handling request: {e}\n')
            sys.stderr.flush()
if __name__ == '__main__':
    main()