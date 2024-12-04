<?php

include 'lib/Database.php';
include_once 'lib/Session.php';


class Users
{


  // Db Property
  private $db;

  // Db __construct Method
  public function __construct()
  {
    $this->db = new Database();
  }

  // Date formate Method
  public function formatDate($date)
  {
    // date_default_timezone_set('Asia/Dhaka');
    $strtime = strtotime($date);
    return date('Y-m-d H:i:s', $strtime);
  }



  // Check Exist Username Address Method
  public function checkExistUsername($username)
  {
    $sql = "SELECT username from  tbl_users WHERE username = :username";
    $stmt = $this->db->pdo->prepare($sql);
    $stmt->bindValue(':username', $username);
    $stmt->execute();
    if ($stmt->rowCount() > 0) {
      return true;
    } else {
      return false;
    }
  }



  // User Registration Method
  public function userRegistration($data)
  {
    $name = $data['name'];
    $username = $data['username'];
    $id_telegram = $data['id_telegram'];
    $username_telegram = $data['userame_telegram'];
    $roleid = $data['roleid'];
    $password = $data['password'];
    $subdistrict = $data['subdistrict'];
    $corpId = $data['corpId'];

    $checkUsername = $this->checkExistUsername($username);

    if ($name == "" || $username == "" || $id_telegram == "" || $username_telegram == "" || $password == "" || $subdistrict == "" || $corpId == "") {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Please, User Registration field must not be Empty !</div>';
      return $msg;
    } elseif (strlen($username) < 3) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Username is too short, at least 3 Characters !</div>';
      return $msg;
    } elseif (filter_var($id_telegram, FILTER_SANITIZE_NUMBER_INT) == FALSE) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Enter only Number Characters for ID Telegram field !</div>';
      return $msg;
    } elseif (strlen($password) < 5) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Password at least 6 Characters !</div>';
      return $msg;
    } elseif (!preg_match("#[0-9]+#", $password)) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Your Password Must Contain At Least 1 Number !</div>';
      return $msg;
    } elseif (!preg_match("#[a-z]+#", $password)) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Your Password Must Contain At Least 1 Number !</div>';
      return $msg;
    } elseif ($checkUsername == TRUE) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Username already Exists, please try another Username... !</div>';
      return $msg;
    } else {

      $sql = "INSERT INTO tbl_users(name, username, id_telegram, password, username_telegram, roleid, subdistrict, corpId) VALUES(:name, :username, :id_telegram, :password, :username_telegram, :roleid, :subdistrict, :corpId)";
      $stmt = $this->db->pdo->prepare($sql);
      $stmt->bindValue(':name', $name);
      $stmt->bindValue(':username', $username);
      $stmt->bindValue(':id_telegram', $id_telegram);
      $stmt->bindValue(':password', $this->HashPass($password));
      $stmt->bindValue(':username_telegram', $username_telegram);
      $stmt->bindValue(':roleid', $roleid);
      $stmt->bindValue(':subdistrict', $subdistrict);
      $stmt->bindValue(':corpId', $corpId);
      $result = $stmt->execute();
      if ($result) {
        $msg = '<div class="alert alert-success alert-dismissible mt-3" id="flash-msg">
  <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
  <strong>Success !</strong> Wow, you have Registered Successfully !</div>';
        return $msg;
      } else {
        $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
  <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
  <strong>Error !</strong> Something went Wrong !</div>';
        return $msg;
      }
    }
  }
  // Add New User By Admin
  public function addNewUserByAdmin($data)
  {
    $name = $data['name'];
    $username = $data['username'];
    $id_telegram = $data['id_telegram'];
    $username_telegram = $data['userame_telegram'];
    $roleid = $data['roleid'];
    $password = $data['password'];
    $subdistrict = $data['subdistrict'];
    $corpId = $data['corpId'];


    $checkUsername = $this->checkExistUsername($username);

    if ($name == "" || $username == "" || $id_telegram == "" || $username_telegram == "" || $password == "" || $subdistrict == "" || $corpId == "") {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Input fields must not be Empty !</div>';
      return $msg;
    } elseif (strlen($username) < 3) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Username is too short, at least 3 Characters !</div>';
      return $msg;
    } elseif (filter_var($id_telegram, FILTER_SANITIZE_NUMBER_INT) == FALSE) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Enter only Number Characters for ID Telegram field !</div>';
      return $msg;
    } elseif (strlen($password) < 5) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Password at least 6 Characters !</div>';
      return $msg;
    } elseif (!preg_match("#[0-9]+#", $password)) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Your Password Must Contain At Least 1 Number !</div>';
      return $msg;
    } elseif (!preg_match("#[a-z]+#", $password)) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Your Password Must Contain At Least 1 Number !</div>';
      return $msg;
    } elseif ($checkUsername == TRUE) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
<a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
<strong>Error !</strong> Username already Exists, please try another Username... !</div>';
      return $msg;
    } else {

      $sql = "INSERT INTO tbl_users(name, username, id_telegram, password, username_telegram, roleid, subdistrict, corpId) VALUES(:name, :username, :id_telegram, :password, :username_telegram, :roleid, :subdistrict, :corpId)";
      $stmt = $this->db->pdo->prepare($sql);

      $stmt->bindValue(':name', $name);
      $stmt->bindValue(':username', $username);
      $stmt->bindValue(':id_telegram', $id_telegram);
      $stmt->bindValue(':password', $this->HashPass($password));
      $stmt->bindValue(':username_telegram', $username_telegram);
      $stmt->bindValue(':roleid', $roleid);
      $stmt->bindValue(':subdistrict', $subdistrict);
      $stmt->bindValue(':corpId', $corpId);
      $result = $stmt->execute();
      if ($result) {
        $msg = '<div class="alert alert-success alert-dismissible mt-3" id="flash-msg">
  <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
  <strong>Success !</strong> Wow, you have Registered Successfully !</div>';
        return $msg;
      } else {
        $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
  <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
  <strong>Error !</strong> Something went Wrong !</div>';
        return $msg;
      }
    }
  }



  // Select All User Method
  public function selectAllUserData()
  {
    $sql = "SELECT * FROM tbl_users ORDER BY id DESC";
    $stmt = $this->db->pdo->prepare($sql);
    $stmt->execute();
    return $stmt->fetchAll(PDO::FETCH_OBJ);
  }


  // User login Autho Method
  public function userLoginAutho($username, $password)
  {
    // $password = $this->HashPass($password);
    $sql = "SELECT * FROM tbl_users WHERE username = :username LIMIT 1";
    $stmt = $this->db->pdo->prepare($sql);
    $stmt->bindValue(':username', $username);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_OBJ);

    if ($user) {
      // echo($user->password);
      // $pass = 'programmerpalugada';
      // $hash = '$2b$08$GznqQlgUmOC0u46pMAuNTOHszQ4DmtTfS/rzPXssiHzlPV1lvwI5S';
      // var_dump(password_verify($pass, $hash));
      //   exit();
      // If the user exists, verify the password
      if (password_verify($password, $user->password)) {
        
        // Password cocok, login berhasil
        return $user; // Atau kembalikan data user atau token autentikasi
      } else {
        // Password does not match
        return false; // Or return an error message
      }
    } else {
      // No user found with the provided username
      return false; // Or return an error message
    }
  }
  // Check User Account Satatus
  public function CheckActiveUser($username)
  {
    $sql = "SELECT * FROM tbl_users WHERE username = :username and isActive = :isActive LIMIT 1";
    $stmt = $this->db->pdo->prepare($sql);
    $stmt->bindValue(':username', $username);
    $stmt->bindValue(':isActive', 1);
    $stmt->execute();
    return $stmt->fetch(PDO::FETCH_OBJ);
  }




  // User Login Authotication Method
  public function userLoginAuthotication($data)
  {
    $username = $data['username'];
    $password = $data['password'];


    $checkUsername = $this->checkExistUsername($username);

    if ($username == "" || $password == "") {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
  <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
  <strong>Error !</strong> Username or Password not be Empty !</div>';
      return $msg;
    } elseif ($checkUsername == FALSE) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
  <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
  <strong>Error !</strong> Username did not Found, use Register username or password please !</div>';
      return $msg;
    } else {


      $logResult = $this->userLoginAutho($username, $password);
      $chkActive = $this->CheckActiveUser($username);

      if ($chkActive == TRUE) {
        $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
    <strong>Error !</strong> Sorry, Your account is Diactivated, Contact with Admin !</div>';
        return $msg;
      } elseif ($logResult) {

        Session::init();
        Session::set('login', TRUE);
        Session::set('id', $logResult->id);
        Session::set('roleid', $logResult->roleid);
        Session::set('name', $logResult->name);
        Session::set('id_telegram', $logResult->id_telegram);
        Session::set('username', $logResult->username);
        Session::set('subdistrict', $logResult->subdistrict);
        Session::set('corpId', $logResult->corpId);
        Session::set('logMsg', '<div class="alert alert-success alert-dismissible mt-3" id="flash-msg">
    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
    <strong>Success !</strong> You are Logged In Successfully !</div>');
        echo "<script>location.href='index.php';</script>";
      } else {
        $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
    <strong>Error !</strong> Username or Password did not Matched !</div>';
        return $msg;
      }
    }
  }



  // Get Single User Information By Id Method
  public function getUserInfoById($userid)
  {
    $sql = "SELECT * FROM tbl_users WHERE id = :id LIMIT 1";
    $stmt = $this->db->pdo->prepare($sql);
    $stmt->bindValue(':id', $userid);
    $stmt->execute();
    $result = $stmt->fetch(PDO::FETCH_OBJ);
    if ($result) {
      return $result;
    } else {
      return false;
    }
  }



  //
  //   Get Single User Information By Id Method
  public function updateUserByIdInfo($userid, $data)
  {
    $name = $data['name'];
    $username = $data['username'];
    $id_telegram = $data['id_telegram'];
    $username_telegram = $data['username_telegram'];
    $roleid = $data['roleid'];
    $subdistrict = $data['subdistrict'];
    $corpId = $data['corpId'];



    if ($name == "" || $username == "" || $id_telegram == "" || $username_telegram == "" || $subdistrict == "" || $corpId == "") {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
  <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
  <strong>Error !</strong> Input Fields must not be Empty !</div>';
      return $msg;
    } elseif (strlen($username) < 3) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
    <strong>Error !</strong> Username is too short, at least 3 Characters !</div>';
      return $msg;
    } elseif (filter_var($id_telegram, FILTER_SANITIZE_NUMBER_INT) == FALSE) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
    <strong>Error !</strong> Enter only Number Characters for ID Telegram field !</div>';
      return $msg;
    } else {

      $sql = "UPDATE tbl_users SET
          name = :name,
          username = :username,
          id_telegram = :id_telegram,
          username_telegram = :username_telegram,
          roleid = :roleid,
          subdistrict = :subdistrict,
          corpId = :corpId
          WHERE id = :id";
      $stmt = $this->db->pdo->prepare($sql);
      $stmt->bindValue(':name', $name);
      $stmt->bindValue(':username', $username);
      $stmt->bindValue(':id_telegram', $id_telegram);
      $stmt->bindValue(':username_telegram', $username_telegram);
      $stmt->bindValue(':roleid', $roleid);
      $stmt->bindValue(':subdistrict', $subdistrict);
      $stmt->bindValue(':corpId', $corpId);
      $stmt->bindValue(':id', $userid);
      $result =   $stmt->execute();

      if ($result) {
        echo "<script>location.href='index.php';</script>";
        Session::set('msg', '<div class="alert alert-success alert-dismissible mt-3" id="flash-msg">
          <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
          <strong>Success !</strong> Wow, Your Information updated Successfully !</div>');
      } else {
        echo "<script>location.href='index.php';</script>";
        Session::set('msg', '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
    <strong>Error !</strong> Data not inserted !</div>');
      }
    }
  }




  // Delete User by Id Method
  public function deleteUserById($remove)
  {
    $sql = "DELETE FROM tbl_users WHERE id = :id ";
    $stmt = $this->db->pdo->prepare($sql);
    $stmt->bindValue(':id', $remove);
    $result = $stmt->execute();
    if ($result) {
      $msg = '<div class="alert alert-success alert-dismissible mt-3" id="flash-msg">
    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
    <strong>Success !</strong> User account Deleted Successfully !</div>';
      return $msg;
    } else {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
    <strong>Error !</strong> Data not Deleted !</div>';
      return $msg;
    }
  }

  // User Deactivated By Admin
  public function userDeactiveByAdmin($deactive)
  {
    $sql = "UPDATE tbl_users SET

       isActive=:isActive
       WHERE id = :id";

    $stmt = $this->db->pdo->prepare($sql);
    $stmt->bindValue(':isActive', 1);
    $stmt->bindValue(':id', $deactive);
    $result =   $stmt->execute();
    if ($result) {
      echo "<script>location.href='index.php';</script>";
      Session::set('msg', '<div class="alert alert-success alert-dismissible mt-3" id="flash-msg">
          <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
          <strong>Success !</strong> User account Diactivated Successfully !</div>');
    } else {
      echo "<script>location.href='index.php';</script>";
      Session::set('msg', '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
    <strong>Error !</strong> Data not Diactivated !</div>');

      // return $msg;
    }
  }


  // User Deactivated By Admin
  public function userActiveByAdmin($active)
  {
    $sql = "UPDATE tbl_users SET
       isActive=:isActive
       WHERE id = :id";

    $stmt = $this->db->pdo->prepare($sql);
    $stmt->bindValue(':isActive', 0);
    $stmt->bindValue(':id', $active);
    $result =   $stmt->execute();
    if ($result) {
      echo "<script>location.href='index.php';</script>";
      Session::set('msg', '<div class="alert alert-success alert-dismissible mt-3" id="flash-msg">
          <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
          <strong>Success !</strong> User account activated Successfully !</div>');
    } else {
      echo "<script>location.href='index.php';</script>";
      Session::set('msg', '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
    <strong>Error !</strong> Data not activated !</div>');
    }
  }




  // Check Old password method
  public function CheckOldPassword($userid, $old_pass)
  {
    $old_pass = $this->HashPass($old_pass);
    $sql = "SELECT password FROM tbl_users WHERE password = :password AND id =:id";
    $stmt = $this->db->pdo->prepare($sql);
    $stmt->bindValue(':password', $old_pass);
    $stmt->bindValue(':id', $userid);
    $stmt->execute();
    if ($stmt->rowCount() > 0) {
      return true;
    } else {
      return false;
    }
  }

  public function HashPass($password)
  {
    // Set the bcrypt salt rounds to 8
    $saltRounds = 8;

    // Hash the password using bcrypt with 8 salt rounds
    $hashedPassword = password_hash($password, PASSWORD_BCRYPT, ['cost' => $saltRounds]);

    if ($hashedPassword === false) {
      throw new Exception('Password hashing failed');
    }

    return $hashedPassword;
  }



  // Change User pass By Id
  public  function changePasswordBysingelUserId($userid, $data)
  {

    $old_pass = $data['old_password'];
    $new_pass = $data['new_password'];


    if ($old_pass == "" || $new_pass == "") {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
  <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
  <strong>Error !</strong> Password field must not be Empty !</div>';
      return $msg;
    } elseif (strlen($new_pass) < 6) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
  <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
  <strong>Error !</strong> New password must be at least 6 character !</div>';
      return $msg;
    }

    $oldPass = $this->CheckOldPassword($userid, $old_pass);
    if ($oldPass == FALSE) {
      $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
     <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
     <strong>Error !</strong> Old password did not Matched !</div>';
      return $msg;
    } else {
      $new_pass = $this->HashPass($new_pass);
      $sql = "UPDATE tbl_users SET

            password=:password
            WHERE id = :id";

      $stmt = $this->db->pdo->prepare($sql);
      $stmt->bindValue(':password', $new_pass);
      $stmt->bindValue(':id', $userid);
      $result =   $stmt->execute();

      if ($result) {
        echo "<script>location.href='index.php';</script>";
        Session::set('msg', '<div class="alert alert-success alert-dismissible mt-3" id="flash-msg">
            <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
            <strong>Success !</strong> Great news, Password Changed successfully !</div>');
      } else {
        $msg = '<div class="alert alert-danger alert-dismissible mt-3" id="flash-msg">
      <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
      <strong>Error !</strong> Password did not changed !</div>';
        return $msg;
      }
    }
  }
}
