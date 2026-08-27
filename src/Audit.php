<?php
namespace GlpiPlugin\Securescan;
final class Audit
{
    public static function record(string $type,array $result,string $file,?object $item=null): void {
        self::write(['time'=>date('c'),'type'=>$type,'status'=>$result['status']??($result['ok']?'clean':'error'),'exit_code'=>$result['exit_code']??null,'size'=>is_file($file)?filesize($file):null,'sha256'=>is_file($file)?hash_file('sha256',$file):null,'temporary'=>is_file($file)?basename($file):null,'itemtype'=>$item!==null?$item::class:null,'items_id'=>self::getItemId($item),'user_id'=>class_exists('Session')?(int)\Session::getLoginUserID():0]);
    }
    public static function recordStored(string $type,string $status,?int $size,?string $sha256,?object $item=null): void {
        self::write(['time'=>date('c'),'type'=>$type,'status'=>$status,'exit_code'=>0,'size'=>$size,'sha256'=>$sha256,'temporary'=>null,'itemtype'=>$item!==null?$item::class:null,'items_id'=>self::getItemId($item),'user_id'=>class_exists('Session')?(int)\Session::getLoginUserID():0]);
        self::writeDocumentHistory($status,$sha256,$item);
    }
    private static function writeDocumentHistory(string $status,?string $sha256,?object $item): void {
        if ($item===null||!method_exists($item,'getID')) return; $id=(int)$item->getID(); if($id<=0)return;
        $message=$status==='clean'?sprintf(__('SecureScan: file scanned successfully and stored. Result: clean. SHA-256: %s','securescan'),$sha256??'N/A'):sprintf(__('SecureScan: file scanned and stored. Result: %s. SHA-256: %s','securescan'),$status,$sha256??'N/A');
        try { \Log::history($id,$item::class,[0,'',$message],0,\Log::HISTORY_LOG_SIMPLE_MESSAGE); } catch(\Throwable $e) { \Toolbox::logDebug($e); }
    }
    private static function getItemId(?object $item): int { return $item!==null&&isset($item->fields['id'])?(int)$item->fields['id']:0; }
    private static function write(array $record): void { $json=json_encode($record,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE); if($json!==false) \Toolbox::logInFile('securescan',$json.PHP_EOL); }
}
