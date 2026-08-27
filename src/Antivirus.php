<?php
namespace GlpiPlugin\Securescan;
use Session;
final class Antivirus
{
    private static array $pendingScans=[];
    public static function preDocumentAdd($item): void { self::scanDocumentInput($item); }
    public static function preDocumentUpdate($item): void { self::scanDocumentInput($item); }
    private static function scanDocumentInput($item): void {
        if (!$item instanceof \Document) return;
        $config=Config::getConfig();
        if (empty($config['securescan_enabled'])) return;
        $upload=self::extractUploadPath($item->input);
        if (!$upload['present']) return;
        if ($upload['path']===null) { self::rejectUpload($item,__('SecureScan could not locate the temporary uploaded file.','securescan'),null); return; }
        $result=self::scan($upload['path'],(string)$config['securescan_command']);
        Audit::record('document',$result,$upload['path'],$item);
        if ($result['ok']) self::$pendingScans[spl_object_id($item)]=['status'=>(string)($result['status']??'clean'),'sha256'=>is_file($upload['path'])?hash_file('sha256',$upload['path']):null,'size'=>is_file($upload['path'])?filesize($upload['path']):null];
        if (!$result['ok']) self::rejectUpload($item,$result['message'],$upload['path']);
    }
    public static function postDocumentAdd($item): void { self::recordStoredDocument($item); }
    public static function postDocumentUpdate($item): void { self::recordStoredDocument($item); }
    private static function recordStoredDocument($item): void {
        if (!$item instanceof \Document) return;
        $key=spl_object_id($item); if (!isset(self::$pendingScans[$key])) return;
        $pending=self::$pendingScans[$key]; unset(self::$pendingScans[$key]);
        Audit::recordStored('document_stored',$pending['status'],$pending['size'],$pending['sha256'],$item);
    }
    public static function test(string $command): array {
        $tmp=tempnam(sys_get_temp_dir(),'securescan_');
        if ($tmp===false) return ['ok'=>false,'message'=>__('Unable to create the temporary test file.','securescan')];
        try { if (file_put_contents($tmp,"SecureScan antivirus test\n")===false) return ['ok'=>false,'message'=>__('Unable to write the temporary test file.','securescan')]; $result=self::scan($tmp,$command,true); Audit::record('test',$result,$tmp); return $result; } finally { @unlink($tmp); }
    }
    private static function rejectUpload($item,string $message,?string $file): void { if ($file!==null && is_file($file)) @unlink($file); $item->input=[]; Session::addMessageAfterRedirect($message,false,ERROR); }
    private static function extractUploadPath(array $input): array {
        if (!empty($input['_filename']) && is_array($input['_filename'])) { $filename=reset($input['_filename']); return ['present'=>true,'path'=>is_string($filename)?self::resolveUploadPath(GLPI_TMP_DIR,$filename):null]; }
        if (!empty($input['upload_file']) && is_string($input['upload_file'])) return ['present'=>true,'path'=>self::resolveUploadPath(GLPI_UPLOAD_DIR,$input['upload_file'])];
        return ['present'=>false,'path'=>null];
    }
    private static function resolveUploadPath(string $directory,string $filename): ?string { if ($filename==='' || strpbrk($filename,'/\\')!==false) return null; $path=rtrim($directory,'/\\').DIRECTORY_SEPARATOR.$filename; return is_file($path)&&is_readable($path)?$path:null; }
    private static function scan(string $file,string $template,bool $test=false): array {
        if (!is_file($file)||!is_readable($file)) return ['ok'=>false,'message'=>__('SecureScan could not access the temporary file.','securescan')];
        if (!function_exists('exec')) return ['ok'=>false,'message'=>__('SecureScan requires the PHP exec() function to be available.','securescan')];
        if (strpos($template,'{file}')===false) return ['ok'=>false,'message'=>__('The antivirus command must contain the {file} placeholder.','securescan')];
        if (!self::isSafeTemplate($template)) return ['ok'=>false,'message'=>__('The command contains forbidden characters or operators.','securescan')];
        $resolved=self::resolveExecutable($template);
        if ($resolved===null) return ['ok'=>false,'message'=>__('SecureScan could not find the antivirus executable for the PHP process. Verify the command path and the web server/PHP user permissions.','securescan'),'status'=>'error','output'=>'','exit_code'=>255];
        $command=str_replace('{file}',escapeshellarg($file),$resolved); $output=[]; $exitCode=255; exec($command.' 2>&1',$output,$exitCode);
        if ($exitCode===0) return ['ok'=>true,'message'=>$test?__('The antivirus responded successfully and the test file is clean.','securescan'):'','status'=>'clean','output'=>implode("\n",$output),'exit_code'=>0];
        if ($exitCode===1) return ['ok'=>false,'message'=>__('The antivirus detected a threat. The file was rejected.','securescan'),'status'=>'infected','output'=>implode("\n",$output),'exit_code'=>1];
        return ['ok'=>false,'message'=>sprintf(__('SecureScan could not complete the antivirus scan (code %d). The file was rejected.','securescan'),$exitCode),'status'=>'error','output'=>implode("\n",$output),'exit_code'=>$exitCode];
    }
    private static function resolveExecutable(string $template): ?string {
        if (!preg_match('/^\s*(\S+)(.*)$/s',$template,$m)) return null; $exe=$m[1]; $args=$m[2]; if ($exe==='') return null;
        if (str_contains($exe,'/')||str_contains($exe,'\\')) return is_executable($exe)?$exe.$args:null;
        $paths=array_filter(explode(PATH_SEPARATOR,getenv('PATH')?:'')); foreach(['/usr/bin','/usr/local/bin','/bin','/usr/sbin','/sbin'] as $p) if(!in_array($p,$paths,true)) $paths[]=$p;
        foreach($paths as $p){$candidate=rtrim($p,'/\\').DIRECTORY_SEPARATOR.$exe;if(is_executable($candidate)&&is_file($candidate))return $candidate.$args;} return null;
    }
    private static function isSafeTemplate(string $template): bool {
        if (preg_match('/[;&|`$<>#\x00\r\n]/',$template)) return false;
        if (preg_match('/\b(?:rm|mv|cp|del|erase|format|powershell|pwsh|cmd|sh|bash)\b/i',$template)) return false;
        return substr_count($template,'{file}')===1;
    }
}
