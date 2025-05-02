<?php
declare (strict_types = 1);

namespace app\middleware;

use app\common\exception\JsonException;
use app\common\enums\ErrorCode;
use think\facade\Response;
use think\Request;

class Decrypt
{
    /**
     * 处理请求
     *
     * @param \think\Request $request
     * @param \Closure       $next
     * @return Response
     */
    public function handle($request, \Closure $next)
    {
        // 这里是解决跨域问题
        if(!$request->isCli())
        {
            header('Access-Control-Allow-Origin:*');
            header('Access-Control-Allow-Methods:GET,POST,PUT,DELETE,PATCH,OPTIONS');
            header('Access-Control-Allow-Headers:Content-Type, X-ELEME-USERID, X-Eleme-RequestID, X-Shard,X-Shard, X-Eleme-RequestID,X-Companyid,X-Adminid,X-Token');
        }

        if ($request->isOptions())
        {
            return Response::create()->send();
            die();
        }

        // 添加中间件执行代码
        $mini_sign = $request->param('mini_sign'); // 前端传的加密后的参数
        if (!empty($mini_sign)) {
            // 参数解密
            // 获取加密密钥和向量（跟前端保持一致，可写在配置里）
            $mini_secret = 'lfKARxycJnB0iIiy0l3/iA==';
            $mini_iv = 'azxGaqxq/BSTTXEjj0/87w==';
            //2：通过request获取前端传入的 $mini_sign数据
            $mini_sign = str_replace(' ','+',$mini_sign);
            //3：对$str_one数据进行解密
            $str = openssl_decrypt($mini_sign, 'AES-128-CBC',$mini_secret,0, $mini_iv);
            //4：对解密后的数据进行 json_decode() 处理
            $arr_one = json_decode($str, JSON_UNESCAPED_UNICODE);
            //5：获取签名 sign
            $sign = $arr_one['sign'];
            //6：去除$arr_one数组中的sign键值对
            unset($arr_one['sign']);
            $signData = $arr_one;
            //7：对数组$arr_one，依据键值，做升序排序（去掉数组，对象）
            foreach ($signData as $key => $val) {
                if (is_array($val) || is_object($val) || is_bool($val)) {
                    unset($signData[$key]);
                }
            }
            ksort($signData);
            //8：对排序后的数组 $arr_one，构造成字符串$str_one,构建的字符串格式类似于 A=a&B=b&C=c
            $str_one = http_build_query($signData);

            //9：构建字符串
            $str_two = $str_one . '&'. $mini_secret . '&' .$mini_iv;
            $str_two = urldecode($str_two);

            //10：生成验证签名字符串 $check_sign
            $check_sign = md5($str_two);

            //11：判断 $sign 是否与 $check_sign 相同；
            if ($check_sign != $sign) {
                throw new JsonException(10001, "签名不合法。");
            }
            // 这里将原始的请求参数加到请求对象里面去，这样控制器里面通过request对象就可以拿到对应参数
            if ($request->isGet()) {
                $request->withGet($arr_one);
            }
            if ($request->isPost()) {
                $request->withPost($arr_one);
            }
            // 这里的代码是为了解决，部分控制器使用request()->param()方法获取不到参数的问题
            foreach ($arr_one as $key => $val) {
                $request->__set($key,$val);
            }
        }
        return $next($request);
    }
}
