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

        // WebHook
        $this->RegisterPropertyString('WebHookPath', 'symconbridge');

        // UI
        $this->RegisterPropertyInteger('UiRootID', 0);
        $this->RegisterPropertyString('UiFilter', '');
        $this->RegisterPropertyInteger('UiPageSize', 50);

        // Git update
        $this->RegisterPropertyString('RepoPath', '/var/lib/symcon/modules/symcon-bridge');

        // Debug
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
    // UI actions
    // -------------------------

    public function UiPing(): void
    {
        $this->UpdateFormField('LastResultLabel', 'caption', 'pong=' . time());
    }

    public function UiShowHook(): void
    {
        $hook = trim($this->ReadPropertyString('WebHookPath'));
        if ($hook === '') {
            $hook = 'symconbridge';
        }
        $this->UpdateFormField('LastResultLabel', 'caption', '/hook/' . $hook);
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
            if (!is_array($items)) {
                $items = [];
            }
        }

        // Nur die Spaltenwerte (scalars) für die List
        $rows = [];
        foreach ($items as $it) {
            $rows[] = [
                'var_id'     => (int)($it['var_id'] ?? 0),
                'name'       => (string)($it['name'] ?? ''),
                'path'       => (string)($it['path'] ?? ''),
                'type_text'  => (string)($it['type_text'] ?? ''),
                'profile'    => (string)($it['profile'] ?? ''),
                'value_text' => (string)($it['value_text'] ?? '')
            ];
        }

        // Manche Symcon-Versionen erwarten JSON-String bei "values"
        $this->UpdateFormField('VarList', 'values', json_encode($rows, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

        $total = (int)($decoded['result']['total'] ?? 0);
        $this->UpdateFormField('LastResultLabel', 'caption', 'total=' . $total);
    }

    public function UpdateFromGit(): void
    {
        $repo = trim($this->ReadPropertyString('RepoPath'));
        if ($repo === '') {
            $repo = '/var/lib/symcon/modules/symcon-bridge';
        }

        if (!is_dir($repo . '/.git')) {
            $this->UpdateFormField('UpdateLogLabel', 'caption', 'Kein Git-Repo unter: ' . $repo);
            return;
        }

        $cmd = 'cd ' . escapeshellarg($repo) . ' && git pull 2>&1';
        $out = @shell_exec($cmd);

        if ($out === null) {
            $out = "shell_exec liefert null. Vermutlich deaktiviert oder keine Rechte.\n" .
                   "Workaround: git pull extern machen (SSH/cron) und hier nur ApplyChanges/ReloadForm nutzen.";
        }

        if (mb_strlen($out) > 1500) {
            $out = mb_substr($out, 0, 1497) . '...';
        }

        $this->UpdateFormField('UpdateLogLabel', 'caption', $out);

        // Ohne Symcon-Neustart: Instanz neu anwenden + UI reloaden
        IPS_ApplyChanges($this->InstanceID);
        $this->ReloadForm();
    }

    // -------------------------
    // Public functions (Scripts)
    // -------------------------

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
                return (mb_strpos(mb_strtolower((string)$it['name']), $f) !== false)
                    || (mb_strpos(mb_strtolower((string)$it['path']), $f) !== false);
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
                'type' => (int)$var['VariableType'],
                'type_text' => $this->VarTypeToText((int)$var['VariableType']),
                'value' => GetValue($varID),
                'value_text' => $this->ValueToText(GetValue($varID), (int)$var['VariableType']),
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

    public function SetVar(int $varID, $value): string
    {
        if (!IPS_VariableExists($varID)) {
            return $this->JsonErr('Variable not found', ['var_id' => $varID], 404);
        }

        $var = IPS_GetVariable($varID);
        $coerced = $this->CoerceValueByVarType($value, (int)$var['VariableType']);

        $used = null;
        $ok = false;
        $err = null;

        // Try RequestAction on ident
        $obj = IPS_GetObject($varID);
        $ident = (string)$obj['ObjectIdent'];

        if ($ident !== '') {
            try {
                $used = 'RequestAction';
                $ok = @RequestAction($ident, $coerced);
            } catch (Throwable $t) {
                $err = $t->getMessage();
                $ok = false;
            }
        }

        if (!$ok) {
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
                    $code = ($decoded['ok'] ?? false) ? 200 : (int)($decoded['error']['code'] ?? 500);
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

    private function WalkTreeCollectVars(int $rootID, array &$out): void
    {
        // Root=0 ist gültig
        if ($rootID < 0) {
            return;
        }
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
                $out[] = $this->VarToItem((int)$cid);
            }

            $this->WalkTreeCollectVars((int)$cid, $out);
        }
    }

    private function VarToItem(int $varID): array
    {
        $obj = IPS_GetObject($varID);
        $var = IPS_GetVariable($varID);

        $profile = $var['VariableProfile'] ?: $var['VariableCustomProfile'];
        $value = @GetValue($varID);

        return [
            'var_id' => $varID,
            'name' => (string)$obj['ObjectName'],
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
        if (is_int($v)) return (string)$v;

        if (is_float($v)) {
            $s = rtrim(rtrim(number_format($v, 4, '.', ''), '0'), '.');
            return $s;
        }

        if (is_string($v)) {
            $s = $v;
            if (mb_strlen($s) > 80) $s = mb_substr($s, 0, 77) . '...';
            return $s;
        }

        $s = json_encode($v, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($s === false) $s = (string)$v;
        if (mb_strlen($s) > 80) $s = mb_substr($s, 0, 77) . '...';
        return $s;
    }

    private function CoerceValueByVarType($value, int $varType)
    {
        switch ($varType) {
            case 0:
                if (is_bool($value)) return $value;
                if (is_numeric($value)) return ((int)$value) !== 0;
                $s = mb_strtolower((string)$value);
                return in_array($s, ['1', 'true', 'yes', 'on', 'ein', 'an'], true);

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
            return false; // safe default
        }

        $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        $token = '';

        if ($hdr !== '') {
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
