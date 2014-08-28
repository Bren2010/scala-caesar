import sbt._
import sbt.Keys._

object Build extends Build {
    val root = Project("root", file("."))
        .settings(
            name         := "caesar",
            organization := "com.bren2010",
            version      := "1.0",
            scalaVersion := "2.11.2"
        )
}
