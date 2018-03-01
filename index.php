<?php
use Silex\Application;
use Symfony\Component\HttpFundation\Response;
use Symfony\Component\HttpFundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use \Firebase\JWT\JWT;
use Symfony\Component\VarDumper;
use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Silex\Component\Security\Core\Encoder\JWTEncoder;
use Silex\Component\Security\Http\Authentication;
use Silex\Component\Security\Http\Authentication\Provider\JWTProvider;
use Silex\Component\Security\Http\EntryPoint\JwtAuthenticationEntryPoint;
use Silex\Component\Security\Http\Firewall\JWTListener;

date_default_timezone_set('America/Brasilia');
require_once __DIR__ . '/vendor/autoload.php';

$app = new Application;
$keyToken = 'niceplanet';
$time = time();
//registrando o TWIG//
$app->register(new Silex\Provider\TwigServiceProvider(), array(
	'twig.path'=>'views'
));

$app->register(new Silex\Provider\SessionServiceProvider());
// conexao banco de dados//
$app['entity'] = $app->share(function(){
$dsn = 'mysql:dbname=beer;host=192.168.3.150;charset=utf8';
try{
	$db = new \PDO($dsn, 'root','apoioteste');
}catch(PDOException $e){
	echo "Falha na Conexão:". $e->getMessage();
}
return $db;
});
// habilitando o json //
$app->before(function(Symfony\Component\HttpFoundation\Request $request) { 
	if (0 === strpos($request->headers->get('Content-Type'), 'application/json')) { 
		$data =json_decode($request->getContent(), true); 
		$request->request->replace(is_array($data)? $data : array()); 
	} 
});
//Rota de Login//
// informe o login cadastrado no Database em um JSON com os parametros exemplo={"login":"nome de usuario", "password":"senha dos usuario"}
$app->post('/login', function() use($app, $keyToken, $time){
	$login = $app['request']->request->get("login");
	$password = $app['request']->request->get("password");
	$stmt = $app['entity']->prepare("SELECT id, user_name, email, passwd FROM users WHERE user_name = '$login' AND passwd = '$password' ");
	$stmt->execute();
	$row = $stmt->fetch(\PDO::FETCH_ASSOC);
	$validade_token =$time+1800;//30 minutos
	$header = [
  		'alg' => 'HS256',
  		'typ' => 'JWT'
	];
	//aqui começa o token//
	//$header = json_encode($header);
	$payload = [
		'iss'=>'niceplanet.com',
		'iat'=>$time,
		'exp'=>$validade_token,
		'user_name'=>$row['user_name'],
		'email'=>$row['email']
	];

	$jwt = JWT::encode($payload, $keyToken);
	//condição para setar o token//
	if (count($row) > 0) {
		$add = $app['entity']->prepare("UPDATE users SET token = '$jwt' WHERE id = '".$row['id']."' ");
		$add->execute();
		$add->errorInfo();
		if ($add == true) {
			return $app->json($jwt);
		}
	}
});
//pegando cervejas pelo tipo//
//passe um JSON com os parametros exemplo={"tipo":"tipo da cerveja", "token":"informe o token"}
$app->post('cervejas/tipo', function($tipo) use($app, $keyToken, $time){
	$tipo = $app['request']->request->get('tipo');
	$token = $app['request']->request->get('token');
	try{
		$decoded = JWT::decode($token, $keyToken, array('HS256'));
		$exp_token = $decoded->exp;
	 	$stmt = $app['entity']->prepare("SELECT token FROM users WHERE token = '$token' LIMIT 1 ");
		$stmt->execute();
	 	$row = $stmt->fetch(PDO::FETCH_ASSOC);
	 	if(count($row['token']) == 1){
	 		$stmt = $app['entity'] ->prepare("SELECT nome, estilo, tipo, preco FROM cervejas WHERE tipo= '$tipo'  ");
	  		$stmt->execute();
	  		$pdo = $stmt->fetchAll(PDO::FETCH_ASSOC);
	  		$tempo_token = $exp_token - $time;
	  		return $app->json(array(
	  			"Tempo em Segundos"=>$tempo_token,
	  			"Tipo"=>$pdo
	  			));
	  	}else{
	  		return $app->json(array('error' => "1"));
	  	}	

	} catch (UnexpectedValueException $e) {
		return $app->json($e->getMessage());
	} catch (Exception $e) {
	       return $app->json($e->getMessage());
	}	
})->value('tipo', NULL);
//pagina raiz listando cervejas//
//passe um JSON com o parametro exemplo={"token":"informe o token aqui"}
$app->post('/', function() use($app, $db, $keyToken, $time){
	$token = $app['request']->request->get('token');
	try{
		$decode = JWT::decode($token, $keyToken, array('HS256'));
		$exp_token = $decoded->exp;
		$stmt = $app['entity']->prepare("SELECT token FROM users WHERE token = '$token' ");
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if(count($row['token']) == 1){
			$stmt = $app['entity'] ->prepare('SELECT id, nome, estilo, tipo, preco FROM cervejas');
			$stmt->execute();
			$pdo = $stmt->fetchAll(PDO::FETCH_ASSOC);
			$tempo_token = $exp_token - $time;
			return $app->json(array(
					"Tempo em Segundos"=>$tempo_token,
					"cervejas"=>$pdo
					));
	}else{
		return $app->json(array('error' => "Token Inválido"));
	}
	}catch(UnexpectedValueException $e){
		return $app->json($e->getMessage());
	}catch(Exception $e){
		return $app->json($e->getMessage());
	}
});
// pegando cervejas pela media indormada no JSON //
//passe um JSON com os parametros exemplo={"v-min":"valor minimo da cerveja", "v-max":"valor maximo da cerveja", "token":"informe o token"}
$app->post('cervejas/media', function() use($app, $keyToken, $time){
	$vMin = $app['request']->request->get("v-min");
	$vMax = $app['request']->request->get("v-max");
	$token = $app['request']->request->get("token");
	try{
		$decoded = JWT::decode($token, $keyToken, array('HS256'));
		$exp_token = $decoded->exp;
		$stmt = $app['entity']->prepare("SELECT token FROM users WHERE token = '$token' ");
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if(count($row['token']) == 1){
			$stmt = $app['entity']->prepare("SELECT  nome, estilo, tipo, preco FROM cervejas WHERE preco >= '$vMin' AND preco <= '$vMax' ");
			$stmt->execute();
			$pdo = $stmt->fetchAll(PDO::FETCH_ASSOC);
			return $app->json($pdo);
		}else{
			return $app->json(array('error' => "Token Inválido"));	
		}		
	}catch(UnexpectedValueException $e){
		return $app->json($e->getMessage());
	}catch(Exception $e){
		return $app->json($e->getMessage());
	}
});
$app->post('cervejas/estilo', function() use($app, $time, $keyToken){
	$estilo = $app['request']->request->get("estilo");
	$token = $app['request']->request->get("token");
	try{
		$decoded = JWT::decode($token, $keyToken, array('HS256'));
		$exp_token = $decoded->exp;
		$stmt = $app['entity']->prepare("SELECT token FROM users WHERE token = '$token' ");
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if (count($row['token']) == 1) {
			$stmt = $app['entity']->prepare("SELECT nome, estilo, tipo, preco FROM cervejas WHERE estilo = '$estilo' ");
			$stmt->execute();
			$pdo = $stmt->fetchAll(PDO::FETCH_ASSOC);
			return $app->json($pdo);
		}
	}catch(UnexpectedValueException $e){
		return $app->json($e->getMessage());
	}catch(Exception $e){
		return $app->json($e->getMessage());
	}
});
//Aqui passe criando o login (somente usuarios tipo 1 criam logins), passando um json com os parametros do $app['request'], com um token válido é possivel criar um novo usuario.//
$app->put('/create-login', function() use($app, $db, $keyToken, $time){
	$token = $app['request']->request->get("token");
	try{
		$decoded = JWT::decode($token, $keyToken, array('HS256'));
		$exp_token = $decoded->exp;
		$stmt = $app['entity']->prepare("SELECT token, tipo FROM users WHERE token = '$token' LIMIT 1");
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if($row['tipo'] == 1 ){
			$newUser = $app['request']->request->get("New-User");
			$newPass = $app['request']->request->get("New-Pass");
			$email = $app['request']->request->get("E-mail");
			$tipo = $app['request']->request->get("Tipo");
			$stmt = $app['entity']->prepare("INSERT INTO users (user_name, passwd, email, tipo) VALUES (?, ?, ?, ?)");
			$stmt->bindParam(1, $newUser);
			$stmt->bindParam(2, $newPass);
			$stmt->bindParam(3, $email);
			$stmt->bindParam(4, $tipo);
			$stmt->execute();
			$pdo = $app['entity']->lastInsertId();
			if ($pdo > 0) {
				return $app->json(array(
					"ID"=>$pdo,
					"Sucesso"=>"login criado"
					));
			}else{
				return $app->json(array(
						"ERRO"=>"ERRO AO CRIAR USUÁRIO"
					));
			}
		}else {
			return $app->json(array(
						"ERRO"=>"ERRO"
					));
		}
	}catch(UnexpectedValueException $e){
		return $app->json($e->getMessage());
	}catch(Exception $e){
		return $app->json($e->getMessage());
	}

});
//update de login passando os parametros em um JSON exatamente como estãs nas linhas com $app['request']//
$app->put('/update-login', function() use($app, $db, $keyToken){
	$token = $app['request']->request->get("token");
	try{
		$decoded = JWT::decode($token, $keyToken, array('HS256'));
		$exp_token = $decoded->exp;
		$stmt = $app['entity']->prepare("SELECT token, tipo FROM users WHERE token = '$token' LIMIT 1");
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if($row['tipo'] == 1){
			$upUser = $app['request']->request->get("Up-User");
			$upPass = $app['request']->request->get("Up-Pass");
			$upEmail = $app['request']->request->get("Up-email");
			$id = $app['request']->request->get("ID");
			$stmt = $app['entity']->prepare("UPDATE users SET user_name = :user, passwd = :pass, email =:email WHERE id = :id");
			$stmt->bindParam(':user', $upUser);
			$stmt->bindParam(':pass', $upPass);
			$stmt->bindParam(':email', $upEmail);
			$stmt->bindParam(':id', $id);
			$stmt->execute();
			$pdo = $stmt->rowCount();
			if ($pdo > 0){
				return $app->json("Atualizado com Sucesso"); 
			}else {
				return $app->json("Nada Foi Alterado");
			}
		}else{
			return $app->json(array(
						"ERRO"=>"ERRO"
					));
		}
	}catch(UnexpectedValueException $e){
		return $app->json($e->getMessage());
	}catch(Exception $e){
		return $app->json($e->getMessage());
	}

});
//delete de login passando os parametros em um JSON exatamente como estãs nas linhas com $app['request']//
$app->delete('/delete-user', function() use($app, $keyToken, $time){
	$token = $app['request']->request->get("token");
	try{
		$decoded = JWT::decode($token, $keyToken, array('HS256'));
		$exp_token = $decoded->exp;
		$stmt = $app['entity']->prepare("SELECT token, tipo FROM users WHERE token = '$token' LIMIT 1");
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);	
		if($row['tipo'] == 1){ 
			$id = $app['request']->request->get("ID");
			$stmt = $app['entity']->prepare("DELETE FROM users WHERE id = :id");
			$stmt->bindParam(':id', $id);
			$stmt->execute();
			$pdo = $stmt->rowCount();
			if ($pdo > 0) {
				return $app->json(array(
					"Sucesso"=>"Usuário DELETADO"
					));
			}else{
				return $app->json(array(
					"ERROR"=>"Algo Deu errado."
					));	
			}
		}else{
			return $app->json(array(
						"ERRO"=>"ERRO"
					));
		}
	}catch(UnexpectedValueException $e){
		return $app->json($e->getMessage());
	}catch(Exception $e){
		return $app->json($e->getMessage());
	}
});
$app->put('cervejas/add', function() use($app, $time, $keyToken, $db){
$token = $app['request']->request->get("token");
	try{
		$decoded = JWT::decode($token, $keyToken, array('HS256'));
		$exp_token = $decoded->exp;
		$time_token = $exp_token - $time;
		$stmt = $app['entity']->prepare("SELECT token, tipo FROM users WHERE token = '$token' LIMIT 1");
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if($row['tipo'] == 1 ){
			$add_cerveja = $app['request']->request->get("add-cerveja");
			$add_estilo = $app['request']->request->get("add-estilo");
			$add_tipo = $app['request']->request->get("add-tipo");
			$add_preco = $app['request']->request->get("add-preco");
			$stmt = $app['entity']->prepare("INSERT INTO cervejas (nome, estilo, tipo, preco) VALUES(?, ?, ?, ?)");
			$stmt->bindParam(1, $add_cerveja);
			$stmt->bindParam(2, $add_estilo);
			$stmt->bindParam(3, $add_tipo);
			$stmt->bindParam(4, $add_preco);
			$stmt->execute();
			$pdo = $app['entity']->lastInsertId();
				if ($pdo > 0) {
					return $app->json(array(
						"ID"=>$pdo,
						"Sucesso"=>"Cerveja Adicionada!!!",
						"Tempo-Token"=>$time_token
						));
				}else{
					return $app->json(array(
							"ERRO"=>"ERRO AO ADICIONAR CERVEJA!"
						));
				}
			}else {
				return $app->json(array(
							"ERRO"=>"ERRO"
						));
			}
		}catch(UnexpectedValueException $e){
			return $app->json($e->getMessage());
		}catch(Exception $e){
			return $app->json($e->getMessage());
		}
});
$app->put('cervejas/update', function() use($app, $time, $keyToken, $db){
	$token = $app['request']->request->get("token");
	try{
		$decoded = JWT::decode($token, $keyToken, array('HS256'));
		$exp_token = $decoded->exp;
		$time_token = $exp_token - $time;
		$stmt = $app['entity']->prepare("SELECT token, tipo FROM users WHERE token = '$token' LIMIT 1");
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);
		if($row['tipo'] == 1 ){
			$up_nome = $app['request']->request->get("up_nome");
			$up_estilo = $app['request']->request->get("up_estilo");
			$up_tipo = $app['request']->request->get("up_tipo");
			$up_preco = $app['request']->request->get("up_preco");
			$id = $app['request']->request->get("ID");
			$stmt = $app['entity']->prepare("UPDATE cervejas SET nome = :nome, estilo = :estilo, tipo = :tipo, preco = :preco WHERE id = :id");
			$stmt->bindParam(':nome', $up_nome);
			$stmt->bindParam(':estilo', $up_estilo);
			$stmt->bindParam(':tipo', $up_tipo);
			$stmt->bindParam(':preco', $up_preco);
			$stmt->bindParam(':id', $id);
			$stmt->execute();
			$pdo = $stmt->rowCount();
			if ($pdo > 0){
				return $app->json("Atualizado com Sucesso"); 
			}else {
				return $app->json("Nada Foi Alterado");
			}
		}else{
			return $app->json(array(
						"ERRO"=>"ERRO"
					));
			}	
		}catch(UnexpectedValueException $e){
			return $app->json($e->getMessage());
		}catch(Exception $e){
			return $app->json($e->getMessage());
		}
});
$app->delete('cervejas/delete', function() use($app, $time, $keyToken, $db){
	$token = $app['request']->request->get("token");
	try{
		$decoded = JWT::decode($token, $keyToken, array('HS256'));
		$exp_token = $decoded->exp;
		$stmt = $app['entity']->prepare("SELECT token, tipo FROM users WHERE token = '$token' LIMIT 1");
		$stmt->execute();
		$row = $stmt->fetch(PDO::FETCH_ASSOC);	
		if($row['tipo'] == 1){
			$id = $app['request']->request->get("ID");
			$stmt = $app['entity']->prepare("DELETE FROM cervejas WHERE id = :id");
			$stmt->bindParam(':id', $id);
			$stmt->execute();
			$pdo = $stmt->rowCount();
			if ($pdo > 0) {
				return $app->json(array(
					"Sucesso"=>"Cerveja DELETADA"
					));
			}else{
				return $app->json(array(
					"ERROR"=>"Algo Deu errado."
					));	
			}
		}else{
			return $app->json(array(
						"ERRO"=>"ERRO"
					));
		}

		}catch(UnexpectedValueException $e){
		return $app->json($e->getMessage());
	}catch(Exception $e){
		return $app->json($e->getMessage());
	}
});
//habilitando o debugador//
$app['debug']= true;
$app->run();
