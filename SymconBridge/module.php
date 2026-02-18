<?php

declare(strict_types=1);

class SymconBridge extends IPSModule
{
    public function Create()
    {
        parent::Create();

        // Security
        $this->RegisterPropertyString('AuthToken', '');
        $this->RegisterPropertyBoolean('AllowNoAuth', false);
        $this->RegisterVariableString('LastResult', 'LastResult');
        $this->RegisterPropertyInteger('UiRootID', 0);
        $this->RegisterPropertyString('UiFilter', '');
        $this->RegisterPropertyInteger('UiPageSize', 50);
        // WebHook
        $this->RegisterPropertyString('WebHookPath', 'symconbridge');

        // Optional: Debug
        $this->RegisterPropertyBoolean('DebugLog', false);
    }

    public function ApplyChanges()
    {
        parent::ApplyChanges();

        $hook = trim($this->ReadPropertyString('WebHookPath'));
        if ($hook === '') {
            $hook = 'symconbridge';
        }

        $this->RegisterHook('/hook/' . $hook);
    }

    // -------------------------
    // Public functions (Scripts)
    // -------------------------

    /**
     * List variables with metadata and paging.
     *
     * @return string JSON
     */
    public function ListVariables(int $rootID, string $filter = '', int $page = 1, int $pageSize = 200): string
    {
        $page = max(1, $page);
        $pageSize = min(max(1, $pageSize), 1000);

        $items = [];
        $this->WalkTreeCollectVars($rootID, $items);

        // Filter (case-insensitive substring on path or name)
        $filter = trim($filter);
        if ($filter !== '') {
            $f = mb_strtolower($filter);
            $items = array_values(array_filter($items, function ($it) use ($f) {
                return (mb_strpos(mb_strtolower($it['name']), $f) !== false)
                    || (mb_strpos(mb_strtolower($it['path']), $f) !== false);
            }));
        }

        $total = count($items);
        $totalPages = (int)ceil($total / $pageSize);

        $offset = ($page - 1) * $pageSize;
        $slice = array_slice($items, $offset, $pageSize);

        $out = [
            'ok' => true,
            'result' => [
                'root_id' => $rootID,
                'filter' => $filter,
                'page' => $page,
                'page_size' => $pageSize,
                'total' => $total,
                'total_pages' => $totalPages,
                'items' => $slice
            ]
        ];

        return json_encode($out, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Get value + metadata for a variable.
     *
     * @return string JSON
     */
    public function GetVar(int $varID): string
    {
        if (!IPS_VariableExists($varID)) {
            return $this->JsonErr('Variable not found', ['var_id' => $varID], 404);
        }

        $obj = IPS_GetObject($varID);
        $var = IPS_GetVariable($varID);

        $profile = $var['VariableProfile'] ?: $var['VariableCustomProfile'];
        $profileInfo = null;
        if ($profile !== '' && IPS_VariableProfileExists($profile)) {
            $profileInfo = IPS_GetVariableProfile($profile);
        }

        $out = [
            'ok' => true,
            'result' => [
                'var_id' => $varID,
                'name' => $obj['ObjectName'],
                'path' => $this->BuildPath($varID),
                'type' => $var['VariableType'],
                'value' => GetValue($varID),
                'changed' => $var['VariableChanged'],
                'updated' => $var['VariableUpdated'],
                'profile' => $profile,
                'profile_info' => $profileInfo,
                'ident' => $obj['ObjectIdent'],
                'parent_id' => $obj['ParentID'],
                'instance_id' => $this->FindInstanceIdForObject($varID)
            ]
        ];

        return json_encode($out, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    /**
     * Set value using RequestAction if possible, with fallback to SetValue.
     *
     * @return string JSON
     */
    public function SetVar(int $varID, $value): string
    {
        if (!IPS_VariableExists($varID)) {
            return $this->JsonErr('Variable not found', ['var_id' => $varID], 404);
        }

        $var = IPS_GetVariable($varID);

        // Basic type coercion
        $coerced = $this->CoerceValueByVarType($value, (int)$var['VariableType']);

        $used = null;
        $ok = false;
        $err = null;

        // Try RequestAction on ident chain
        $obj = IPS_GetObject($varID);
        $ident = $obj['ObjectIdent'];

        if ($ident !== '') {
            // RequestAction expects ident (string) and value
            try {
                $used = 'RequestAction';
                $ok = @RequestAction($ident, $coerced);
            } catch (Throwable $t) {
                $err = $t->getMessage();
                $ok = false;
            }
        }

        if (!$ok) {
            // Fallback: direct SetValue (works for many variables, but not all)
            try {
                $used = $used ? ($used . ' -> SetValue') : 'SetValue';
                SetValue($varID, $coerced);
                $ok = true;
            } catch (Throwable $t) {
                $err = $t->getMessage();
                $ok = false;
            }
        }

        if (!$ok) {
            return $this->JsonErr('Set failed', [
                'var_id' => $varID,
                'used' => $used,
                'error' => $err
            ], 500);
        }

        $out = [
            'ok' => true,
            'result' => [
                'var_id' => $varID,
                'used' => $used,
                'value' => GetValue($varID)
            ]
        ];

        return json_encode($out, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    // -------------------------
    // WebHook endpoint
    // -------------------------
    public function ProcessHookData()
    {
        $raw = file_get_contents('php://input');
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

        if ($this->ReadPropertyBoolean('DebugLog')) {
            $this->SendDebug('Hook', $method . ' ' . ($_SERVER['REQUEST_URI'] ?? ''), 0);
            $this->SendDebug('HookBody', $raw, 0);
        }

        // Auth
        if (!$this->IsAuthorized()) {
            $this->SendHookResponse(401, $this->JsonErrArr('Unauthorized', null, 401));
            return;
        }

        if ($method !== 'POST') {
            $this->SendHookResponse(405, $this->JsonErrArr('Use POST', null, 405));
            return;
        }

        $data = json_decode($raw, true);
        if (!is_array($data)) {
            $this->SendHookResponse(400, $this->JsonErrArr('Invalid JSON', null, 400));
            return;
        }

        $action = (string)($data['action'] ?? '');
        $args = $data['args'] ?? [];

        try {
            switch ($action) {
                case 'list_variables': {
                    $root = (int)($args['root_id'] ?? 0);
                    $filter = (string)($args['filter'] ?? '');
                    $page = (int)($args['page'] ?? 1);
                    $pageSize = (int)($args['page_size'] ?? 200);
                    $json = $this->ListVariables($root, $filter, $page, $pageSize);
                    $this->SendHookResponse(200, json_decode($json, true));
                    return;
                }

                case 'get_var': {
                    $varID = (int)($args['var_id'] ?? 0);
                    $json = $this->GetVar($varID);
                    $this->SendHookResponse(200, json_decode($json, true));
                    return;
                }

                case 'set_var': {
                    $varID = (int)($args['var_id'] ?? 0);
                    $value = $args['value'] ?? null;
                    $json = $this->SetVar($varID, $value);
                    $decoded = json_decode($json, true);
                    $code = ($decoded['ok'] ?? false) ? 200 : 500;
                    if (isset($decoded['error']['code'])) {
                        $code = (int)$decoded['error']['code'];
                    }
                    $this->SendHookResponse($code, $decoded);
                    return;
                }

                case 'ping': {
                    $this->SendHookResponse(200, ['ok' => true, 'result' => ['pong' => true, 'time' => time()]]);
                    return;
                }

                default:
                    $this->SendHookResponse(400, $this->JsonErrArr('Unknown action', ['action' => $action], 400));
                    return;
            }
        } catch (Throwable $t) {
            $this->SendHookResponse(500, $this->JsonErrArr('Exception', ['message' => $t->getMessage()], 500));
        }
    }

    // -------------------------
    // Helpers
    // -------------------------


private function VarTypeToText(int $t): string
{
    switch ($t) {
        case 0: return 'bool';
        case 1: return 'int';
        case 2: return 'float';
        case 3: return 'string';
        default: return (string)$t;
    }
}

private function ValueToText($v, int $t): string
{
    if ($v === null) return 'null';

    if (is_bool($v)) return $v ? 'true' : 'false';

    if (is_float($v)) {
        // nicht zu lang
        $s = rtrim(rtrim(number_format($v, 4, '.', ''), '0'), '.');
        return $s;
    }

    if (is_int($v)) return (string)$v;

    if (is_string($v)) {
        $s = $v;
        if (mb_strlen($s) > 80) $s = mb_substr($s, 0, 77) . '...';
        return $s;
    }

    // arrays/objects
    $s = json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    if ($s === false) $s = (string)$v;
    if (mb_strlen($s) > 80) $s = mb_substr($s, 0, 77) . '...';
    return $s;
}
    
  private function WalkTreeCollectVars(int $rootID, array &$out): void
{
    // Symcon Root ist 0 und ist gültig für IPS_GetChildrenIDs(0)
    if ($rootID < 0) {
        return;
    }

    // Nur prüfen, wenn es nicht Root ist
    if ($rootID !== 0 && !IPS_ObjectExists($rootID)) {
        return;
    }

    $children = IPS_GetChildrenIDs($rootID);
    foreach ($children as $cid) {
        if (!IPS_ObjectExists($cid)) {
            continue;
        }

        $o = IPS_GetObject($cid);
        if ($o['ObjectType'] === 2 /* Variable */) {
            $out[] = $this->VarToItem($cid);
        }

        // recurse in jedem Fall
        $this->WalkTreeCollectVars($cid, $out);
    }
}
    private function VarToItem(int $varID): array
    {
        $obj = IPS_GetObject($varID);
        $var = IPS_GetVariable($varID);

        $profile = $var['VariableProfile'] ?: $var['VariableCustomProfile'];

return [
    'var_id' => $varID,
    'name' => $obj['ObjectName'],
    'path' => $this->BuildPath($varID),
    'type' => (int)$var['VariableType'],
    'type_text' => $this->VarTypeToText((int)$var['VariableType']),
    'profile' => (string)$profile,
    'ident' => (string)$obj['ObjectIdent'],
    'parent_id' => (int)$obj['ParentID'],
    'instance_id' => (int)$this->FindInstanceIdForObject($varID),
    'value' => $value,
    'value_text' => $this->ValueToText($value, (int)$var['VariableType'])
];
    }

    private function BuildPath(int $objectID): string
    {
        $parts = [];
        $cur = $objectID;
        while ($cur > 0 && IPS_ObjectExists($cur)) {
            $o = IPS_GetObject($cur);
            array_unshift($parts, $o['ObjectName']);
            $cur = (int)$o['ParentID'];
        }
        return implode(' / ', $parts);
    }

    private function FindInstanceIdForObject(int $objectID): int
    {
        // Walk up until we hit an Instance (ObjectType 1)
        $cur = $objectID;
        while ($cur > 0 && IPS_ObjectExists($cur)) {
            $o = IPS_GetObject($cur);
            if ($o['ObjectType'] === 1) {
                return $cur;
            }
            $cur = (int)$o['ParentID'];
        }
        return 0;
    }

    private function CoerceValueByVarType($value, int $varType)
    {
        // 0=Boolean, 1=Integer, 2=Float, 3=String per IPS
        switch ($varType) {
            case 0:
                if (is_bool($value)) return $value;
                if (is_numeric($value)) return ((int)$value) !== 0;
                $s = mb_strtolower((string)$value);
                return in_array($s, ['1','true','yes','on','ein','an'], true);
            case 1:
                return (int)$value;
            case 2:
                return (float)$value;
            case 3:
            default:
                if (is_array($value) || is_object($value)) {
                    return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                }
                return (string)$value;
        }
    }

    private function IsAuthorized(): bool
    {
        if ($this->ReadPropertyBoolean('AllowNoAuth')) {
            return true;
        }
        $need = trim($this->ReadPropertyString('AuthToken'));
        if ($need === '') {
            // If no token configured, deny by default (safer)
            return false;
        }

        // Accept either header or query param
        $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        $token = '';

        if ($hdr !== '') {
            // Expect: "Bearer <token>" or raw token
            if (stripos($hdr, 'bearer ') === 0) {
                $token = trim(substr($hdr, 7));
            } else {
                $token = trim($hdr);
            }
        }

        if ($token === '') {
            $token = (string)($_GET['token'] ?? '');
        }

        return hash_equals($need, $token);
    }

    private function SendHookResponse(int $statusCode, array $payload): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    private function JsonErr(string $message, $data = null, int $code = 500): string
    {
        return json_encode($this->JsonErrArr($message, $data, $code), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    private function JsonErrArr(string $message, $data = null, int $code = 500): array
    {
        return [
            'ok' => false,
            'error' => [
                'message' => $message,
                'code' => $code,
                'data' => $data
            ]
        ];
    }

    public function UiPing(): void
{
    $this->SetValue('LastResult', json_encode([
        'ok' => true,
        'result' => ['pong' => true, 'time' => time()]
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

    $this->UpdateFormField('LastResultLabel', 'caption', $this->GetValue('LastResult'));
}

public function UiList(): void
{
    $root = (int)$this->ReadPropertyInteger('UiRootID');
    $filter = (string)$this->ReadPropertyString('UiFilter');
    $pageSize = (int)$this->ReadPropertyInteger('UiPageSize');

    $json = $this->ListVariables($root, $filter, 1, $pageSize);
    $decoded = json_decode($json, true);

    $items = [];
    if (is_array($decoded) && ($decoded['ok'] ?? false)) {
        $items = $decoded['result']['items'] ?? [];
        if (!is_array($items)) $items = [];
    }

    // Tabelle füllen
    $this->UpdateFormField('VarList', 'values', json_encode($items));

    // optional: Debug
    $this->SetValue('LastResult', $json);
    $this->UpdateFormField('LastResultLabel', 'caption', 'total=' . (($decoded['result']['total'] ?? 0)) );
}
    
public function UiShowHook(): void
{
    $hook = trim($this->ReadPropertyString('WebHookPath'));
    if ($hook === '') $hook = 'symconbridge';

    $url = '/hook/' . $hook;

    $this->SetValue('LastResult', json_encode([
        'ok' => true,
        'result' => ['hook_path' => $url]
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

    $this->UpdateFormField('LastResultLabel', 'caption', $this->GetValue('LastResult'));
}

// Kleine Safe-Reader (damit nix crasht, falls Keys fehlen)
private function ReadPropertyIntegerSafe(string $name, int $default): int
{
    try { return (int)$this->ReadPropertyInteger($name); } catch (Throwable $t) { return $default; }
}
private function ReadPropertyStringSafe(string $name, string $default): string
{
    try { return (string)$this->ReadPropertyString($name); } catch (Throwable $t) { return $default; }
}
    // WebHook registration helper (standard pattern)
    private function RegisterHook(string $Hook): void
    {
        $ids = IPS_GetInstanceListByModuleID('{015A6EB8-D6E5-4B93-B0F5-0C4E6A7A3E1F}'); // WebHook Control
        if (count($ids) === 0) {
            $this->SendDebug('Hook', 'WebHook Control instance not found', 0);
            return;
        }

        $hookInstanceID = $ids[0];

        $hooks = json_decode(IPS_GetProperty($hookInstanceID, 'Hooks'), true);
        if (!is_array($hooks)) $hooks = [];

        $found = false;
        foreach ($hooks as $h) {
            if (($h['Hook'] ?? '') === $Hook) {
                $found = true;
                break;
            }
        }

        if (!$found) {
            $hooks[] = ['Hook' => $Hook, 'TargetID' => $this->InstanceID];
            IPS_SetProperty($hookInstanceID, 'Hooks', json_encode($hooks));
            IPS_ApplyChanges($hookInstanceID);
        }
    }
}
