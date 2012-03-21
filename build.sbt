name := "oauth_provider"

version := "1.0"

scalaVersion := "2.9.1"

parallelExecution in Test := false

libraryDependencies +=
       "org.scala-tools.testing" %% "scalacheck" % "1.9" % "test"

resolvers += "Typesafe Repository" at "http://repo.typesafe.com/typesafe/releases/"

libraryDependencies += "org.scala-tools.testing" % "specs_2.9.0" % "1.6.8" % "test"

libraryDependencies += "com.typesafe.akka" % "akka-actor" % "2.0"

libraryDependencies += "com.typesafe" %% "play-mini" % "2.0-RC3"
