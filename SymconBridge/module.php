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

        // Registry (persistente JSON-Map in den Instanz-Properties)
        $this->RegisterPropertyString('DeviceRegistry', '{}');

        // UI state: aktuell ausgewählte Var
        $this->RegisterAttributeInteger('SelectedVarID', 0);

        // UI
        $this->RegisterPropertyInteger('UiRootID', 0);
        $this->RegisterPropertyString('UiFilter', '');
        $this->RegisterPropertyInteger('UiPageSize', 50);

        // Git update
        $this->RegisterPropertyString('RepoPath', '/var/lib/symcon/modules/symcon-bridge');

        // Debug
        $this->RegisterPropertyBoolean('DebugLog', false);

        // Registry-Editor Felder (damit wir sie per UpdateFormField setzen können)
        $this->RegisterPropertyString('RegKind', 'light');
        $this->RegisterPropertyString('RegFloor', 'EG');
        $this->RegisterPropertyString('RegRoomSelect', '');
        $this->RegisterPropertyString('RegRoomFree', '');
        $this->RegisterPropertyString('RegName', '');
        $this->RegisterPropertyBoolean('RegEnabled', true);
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

        $this->UpdateFormField('VarList', 'values', json_encode($rows, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

        $total = (int)($decoded['result']['total'] ?? 0);
        $this->UpdateFormField('LastResultLabel', 'caption', 'total=' . $total);
    }

    public function UiSelectVar(int $var_id): void
    {
        $varID = (int)$var_id;
        $this->WriteAttributeInteger('SelectedVarID', $varID);

        if ($varID <= 0 || !IPS_ObjectExists($varID)) {
            $this->UpdateFormField('SelectedVarLabel', 'caption', 'Ausgewählt: -');
            return;
        }

        $o = IPS_GetObject($varID);
        $path = $this->BuildPath($varID);
        $this->UpdateFormField('SelectedVarLabel', 'caption', 'Ausgewählt: ' . $varID . ' | ' . $o['ObjectName'] . ' | ' . $path);

        // Räume-Optionen aktualisieren
        $this->UiRefreshRooms();

        // Registry-Eintrag laden (falls vorhanden), sonst Defaults setzen
        $reg = $this->LoadRegistry();
        $key = (string)$varID;

        if (isset($reg[$key]) && is_array($reg[$key])) {
            $e = $reg[$key];
            $this->UpdateFormField('RegKind', 'value', (string)($e['kind'] ?? 'light'));
            $this->UpdateFormField('RegFloor', 'value', (string)($e['floor'] ?? 'EG'));
            $this->UpdateFormField('RegRoomFree', 'value', (string)($e['room'] ?? ''));
            $this->UpdateFormField('RegName', 'value', (string)($e['name'] ?? $o['ObjectName']));
            $this->UpdateFormField('RegEnabled', 'value', (bool)($e['enabled'] ?? true));
        } else {
            $this->UpdateFormField('RegKind', 'value', 'light');
            $this->UpdateFormField('RegFloor', 'value', 'EG');
            $this->UpdateFormField('RegRoomFree', 'value', '');
            $this->UpdateFormField('RegName', 'value', (string)$o['ObjectName']);
            $this->UpdateFormField('RegEnabled', 'value', true);
        }

        $this->UpdateFormField('LastResultLabel', 'caption', 'Var ausgewählt');
    }

    public function UiSaveRegistry(): void
    {
        $varID = (int)$this->ReadAttributeInteger('SelectedVarID');
        if ($varID <= 0 || !IPS_ObjectExists($varID)) {
            $this->UpdateFormField('LastResultLabel', 'caption', 'Bitte zuerst eine Variable auswählen.');
            return;
        }

        // Werte aus Form holen (Symcon liefert sie als Properties)
        $kind = (string)$this->ReadPropertyString('RegKind');
        $floor = (string)$this->ReadPropertyString('RegFloor');
        $roomSelect = (string)$this->ReadPropertyString('RegRoomSelect');
        $roomFree = (string)$this->ReadPropertyString('RegRoomFree');
        $name = (string)$this->ReadPropertyString('RegName');
        $enabled = (bool)$this->ReadPropertyBoolean('RegEnabled');

        $room = trim($roomFree) !== '' ? trim($roomFree) : trim($roomSelect);

        if ($name === '') {
            $o = IPS_GetObject($varID);
            $name = (string)$o['ObjectName'];
        }

        $reg = $this->LoadRegistry();
        $reg[(string)$varID] = [
            'kind' => $kind,
            'floor' => $floor,
            'room' => $room,
            'name' => $name,
            'enabled' => $enabled
        ];

        $this->SaveRegistry($reg);

        $this->UiRefreshRooms();
        $this->UpdateFormField('LastResultLabel', 'caption', 'Gespeichert: ' . $varID);
    }

    public function UiDeleteRegistry(): void
    {
        $varID = (int)$this->ReadAttributeInteger('SelectedVarID');
        if ($varID <= 0) {
            $this->UpdateFormField('LastResultLabel', 'caption', 'Nichts ausgewählt.');
            return;
        }

        $reg = $this->LoadRegistry();
        unset($reg[(string)$varID]);
        $this->SaveRegistry($reg);

        $this->UiRefreshRooms();
        $this->UpdateFormField('LastResultLabel', 'caption', 'Gelöscht: ' . $varID);
    }
public function UiRefreshRooms(): void
{
    $reg = $this->LoadRegistry();

    $rooms = [];
    foreach ($reg as $e) {
        if (!is_array($e)) continue;
        $r = trim((string)($e['room'] ?? ''));
        if ($r !== '') $rooms[$r] = true;
    }

    ksort($rooms);

    $opts = [];
    // ✅ wichtig: leere Option für "" (damit Symcon nicht meckert)
    $opts[] = ['caption' => '– bitte wählen –', 'value' => ''];

    foreach (array_keys($rooms) as $r) {
        $opts[] = ['caption' => $r, 'value' => $r];
    }

    $this->UpdateFormField('RegRoomSelect', 'options', json_encode(
        $opts,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    ));

    // ✅ sicherstellen, dass aktueller Wert existiert
    $cur = (string)$this->ReadPropertyString('RegRoomSelect');
    if ($cur !== '' && !isset($rooms[$cur])) {
        // Immer einen gültigen Wert setzen, damit Symcon nicht meckert
    $this->UpdateFormField('RegRoomSelect', 'value', (string)$this->ReadPropertyString('RegRoomSelect'));
    }
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

        IPS_ApplyChanges($this->InstanceID);
        $this->ReloadForm();
    }

    // -------------------------
    // Public functions (Scripts / API)
    // -------------------------

    public function ListVariables(int $rootID, string $filter = '', int $page = 1, int $pageSize = 200): string
    {
        $page = max(1, $page);
        $pageSize = min(max(1, $pageSize), 1000);

        $items = [];
        $this->WalkTreeCollectVars($rootID, $items);

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

        $obj = IPS_GetObject($varID);
        $ident = (string)$obj['ObjectIdent'];
        $iid = (int)$this->FindInstanceIdForObject($varID);

        // Bevorzugt: IPS_RequestAction(InstanceID, Ident, Value)
        if ($iid > 0 && $ident !== '') {
            try {
                $used = 'IPS_RequestAction';
                IPS_RequestAction($iid, $ident, $coerced);
                $ok = true;
            } catch (Throwable $t) {
                $err = $t->getMessage();
                $ok = false;
            }
        }

        // Fallback: SetValue
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

    public function ListDevices(): string
    {
        $reg = $this->LoadRegistry();
        $devices = [];

        foreach ($reg as $varIdStr => $e) {
            $varID = (int)$varIdStr;
            if ($varID <= 0 || !IPS_VariableExists($varID)) {
                continue;
            }
            if (!is_array($e)) {
                continue;
            }
            if (!(bool)($e['enabled'] ?? true)) {
                continue;
            }

            $kind = (string)($e['kind'] ?? 'other');
            $name = (string)($e['name'] ?? ('Var ' . $varID));
            $floor = (string)($e['floor'] ?? '');
            $room = (string)($e['room'] ?? '');

            $var = IPS_GetVariable($varID);
            $t = (int)$var['VariableType'];
            $val = @GetValue($varID);

            $cap = $this->CapabilitiesFromVar($t, $var);

            $devices[] = [
                'id' => 'var:' . $varID,
                'name' => $name,
                'kind' => $kind,
                'location' => ['floor' => $floor, 'room' => $room],
                'capabilities' => $cap,
                'state' => $this->StateFromVar($t, $val),
                'symcon' => [
                    'var_id' => $varID,
                    'type' => $t,
                    'profile' => (string)($var['VariableProfile'] ?: $var['VariableCustomProfile'])
                ]
            ];
        }

        return json_encode(['ok' => true, 'devices' => $devices], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
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

                case 'list_devices': {
                    $json = $this->ListDevices();
                    $this->SendHookResponse(200, json_decode($json, true));
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

    private function LoadRegistry(): array
    {
        $raw = (string)$this->ReadPropertyString('DeviceRegistry');
        $data = json_decode($raw, true);
        return is_array($data) ? $data : [];
    }

    private function SaveRegistry(array $reg): void
    {
        $raw = json_encode($reg, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        if ($raw === false) {
            $raw = '{}';
        }
        IPS_SetProperty($this->InstanceID, 'DeviceRegistry', $raw);
        IPS_ApplyChanges($this->InstanceID);
    }

    private function WalkTreeCollectVars(int $rootID, array &$out): void
    {
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
            if ($o['ObjectType'] === 2) { // Variable
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
            if ($o['ObjectType'] === 1) { // Instance
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

    private function ValueToText($v, int $t $this->UpdateFormField('RegRoomSelect', 'value', ''); $this->UpdateFormField('RegRoomSelect', 'value', '');): string
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

    private function CapabilitiesFromVar(int $t, array $var): array
    {
        $profile = (string)($var['VariableProfile'] ?: $var['VariableCustomProfile']);

        if ($t === 0) return ['on_off'];
        if (stripos($profile, 'intensity') !== false) return ['level'];
        if ($t === 1 || $t === 2) return ['level'];
        return ['value'];
    }

    private function StateFromVar(int $t, $val): array
    {
        if ($t === 0) return ['on' => (bool)$val];
        if ($t === 1 || $t === 2) return ['level' => $val];
        return ['value' => $val];
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
