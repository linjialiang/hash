<?php
// +----------------------------------------------------------------------
// | 字符加密与散列验证
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: 地上马 <linjialiang@163.com>
// +----------------------------------------------------------------------

namespace qyadmin;

class Hash
{
    /**
     * [randstr 获取随机字符串]
     * @param  integer $length [字符串长度]
     * @return [type]         [返回随机字符串]
     */
    public function qy_randstr(int $length)
    {
        $length<1 ? $length=1 : false; // 设置字符串最小值，防止字符串过小
    $length>100 ? $length=100 : false; // 获取字符串长度，防止运行时间过长而崩溃

    $str     = '_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $len     = strlen($str) - 1;
        $randstr = '';

        for ($i = 0; $i<$length; $i++) {
            $num = mt_rand(0, $len);
            $randstr .= $str[$num];
        }
        return $randstr;
    }

    /**
     * [qy_cost_value 检测服务器最佳的cost值]
     * @param  string  $text   [测试字符串]
     * @param  float   $time   [响应时间]
     * @param  integer $cost   [cost初始值]
     * @param  integer $length [字符串长度]
     * @param  [type]  $algo   [php内置常量]
     * @return [type]          [输出$cost最佳值]
     */
    public function qy_cost_value(string $text, float $time = 0.05, int $cost = 8, int $length = 10, $algo = PASSWORD_DEFAULT)
    {
        $time<=0 ? $time=0.05 : false;  // $time设置最小值，获得的cost值更加合理
    $time>0.1 ? $time=0.1 : false;  // $time设置最大值，防止无限循环的出现
    $cost<8 ? $cost  = 8 : false;    // $cost设置最小值，散列更加安全
    $cost>13 ? $cost = 13 : false;    // $cost设置最大值，预防执行时服务器崩溃
    strlen($text)<5 ? $text=qy_randstr($length) : false;   // 获取检测字符串

    do {
        $cost++;
        $start = microtime(true);   // 加密前的 微秒数
        password_hash($text, $algo, ['cost' => $cost, ]);
        $end = microtime(true);     // 加密后的 微秒数
    } while (($end - $start) < $time);

        return $cost;
    }

    /**
     * [qy_hash 字符串加密]
     * @param  string  $text [需要加密的字符串]
     * @param  integer $cost [cost初始值]
     * @param  [type]  $algo [php内置常量]
     * @return [type]        [加密后的散列]
     */
    public function qy_hash(string $text, int $cost = 10, $algo = PASSWORD_DEFAULT)
    {
        $cost<8 ? $cost  = 8 : false;    // $cost设置最小值，散列更加安全
    $cost>13 ? $cost = 13 : false;    // $cost设置最大值，预防执行时服务器崩溃

    $hash = password_hash($text, $algo, ['cost' => $cost]);

        return $hash;
    }

    /**
     * [qy_verify 字符串验证]
     * @param  string $text [需要验证的字符串]
     * @param  string $hash [加密后的散列]
     * @return [type]       [返回验证后的布尔值1或空白]
     */
    public function qy_verify(string $text, string $hash)
    {
        return password_verify($text, $hash);
    }
}
